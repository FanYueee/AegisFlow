package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Rule struct {
	ID                string       `json:"id"`
	Name              string       `json:"name"`
	Enabled           bool         `json:"enabled"`
	Source            string       `json:"source"`
	InterfaceKey      string       `json:"interface_key"`
	Direction         string       `json:"direction"`
	Protocol          string       `json:"protocol"`
	Destination       string       `json:"destination"`
	TCPFlags          *uint32      `json:"tcp_flags"`
	Metric            string       `json:"metric"`
	Threshold         float64      `json:"threshold"`
	WindowSeconds     int          `json:"window_seconds"`
	HoldSeconds       int          `json:"hold_seconds"`
	RecoveryThreshold float64      `json:"recovery_threshold"`
	RecoverySeconds   int          `json:"recovery_seconds"`
	CooldownSeconds   int          `json:"cooldown_seconds"`
	Route             RouteRequest `json:"route"`
	LastTriggered     time.Time    `json:"last_triggered"`
}
type ruleRuntime struct {
	Started        time.Time         `json:"-"`
	Buckets        map[int64]float64 `json:"-"`
	LastTraffic    time.Time         `json:"last_traffic"`
	HighSince      time.Time         `json:"-"`
	LowObservation time.Time         `json:"-"`
	LowSince       time.Time         `json:"-"`
	CooldownUntil  time.Time         `json:"cooldown_until"`
	Value          float64           `json:"value"`
	Phase          string            `json:"phase"`
	Error          string            `json:"error,omitempty"`
	RouteID        string            `json:"route_id,omitempty"`
	RouteState     string            `json:"route_state,omitempty"`
	Busy           bool              `json:"busy"`
	Generation     uint64            `json:"-"`
}
type RuleView struct {
	Rule
	Runtime ruleRuntime `json:"runtime"`
}
type RuleFlow struct {
	Received                   time.Time
	Source, Exporter, Protocol string
	InIf, OutIf                uint32
	Destination                netip.Addr
	Flags                      TCPFlagObservation
	Bytes, Packets             float64
}
type ruleJob struct {
	ID         string
	Generation uint64
	Withdraw   bool
	RouteID    string
}
type RuleEngine struct {
	mu               sync.Mutex
	rules            map[string]Rule
	runtime          map[string]*ruleRuntime
	path             string
	control          *Controller
	incoming         chan RuleFlow
	jobs             chan ruleJob
	dropped          atomic.Uint64
	seenDropped      uint64
	readyError       string
	persistenceError string
	now              func() time.Time
}

var liveRules atomic.Pointer[RuleEngine]

func validateRule(r Rule) error {
	if strings.TrimSpace(r.Name) == "" || len(r.Name) > 96 {
		return errors.New("名稱需為 1–96 bytes")
	}
	if r.Source != "sflow" && r.Source != "netflow9" && r.Source != "ipfix" {
		return errors.New("資料來源無效")
	}
	if r.Direction != "IN" && r.Direction != "OUT" {
		return errors.New("方向需為 IN 或 OUT")
	}
	if r.InterfaceKey == "" {
		return errors.New("請選擇監控介面")
	}
	if r.InterfaceKey != "" {
		parts := strings.Split(r.InterfaceKey, "@")
		if len(parts) != 3 || parts[0] != r.Source {
			return errors.New("介面與資料來源不符")
		}
		if _, err := netip.ParseAddr(parts[1]); err != nil {
			return errors.New("介面設備位址無效")
		}
		if _, err := strconv.ParseUint(parts[2], 10, 32); err != nil {
			return errors.New("介面編號無效")
		}
	}
	if r.Protocol != "any" && r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "gre" && r.Protocol != "icmp" && r.Protocol != "other" {
		return errors.New("協定無效")
	}
	if p, err := netip.ParsePrefix(r.Destination); err != nil || p != p.Masked() || p.Addr().Is4In6() {
		return errors.New("監控目的網段需為標準 CIDR")
	}
	if r.TCPFlags != nil && (r.Protocol != "tcp" || *r.TCPFlags > 0xfff) {
		return errors.New("旗標需為 TCP 完整組合")
	}
	if r.Metric != "bps" && r.Metric != "pps" {
		return errors.New("門檻單位需為 bps 或 pps")
	}
	if math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) || r.Threshold <= 0 || math.IsNaN(r.RecoveryThreshold) || math.IsInf(r.RecoveryThreshold, 0) || r.RecoveryThreshold < 0 || r.RecoveryThreshold >= r.Threshold {
		return errors.New("觸發門檻需大於 0，復原門檻需小於觸發門檻且不可為負")
	}
	if r.WindowSeconds < 1 || r.WindowSeconds > 60 || r.HoldSeconds < 0 || r.HoldSeconds > 60 || r.RecoverySeconds < 1 || r.RecoverySeconds > 3600 || r.CooldownSeconds < 1 || r.CooldownSeconds > 3600 {
		return errors.New("視窗 1–60 秒、持續超標 0–60 秒、復原與冷卻 1–3600 秒")
	}
	if err := validateRoute(r.Route, ControlConfig{AllowedPrefixes: []string{r.Route.Prefix}}); err != nil {
		return err
	}

	return nil
}
func freshRuntime(now time.Time, generation uint64) *ruleRuntime {
	return &ruleRuntime{Started: now, Buckets: map[int64]float64{}, Phase: "warming", Generation: generation}
}
func newRuleEngine(path string, c *Controller) (*RuleEngine, error) {
	e := &RuleEngine{path: path, control: c, rules: map[string]Rule{}, runtime: map[string]*ruleRuntime{}, incoming: make(chan RuleFlow, 8192), jobs: make(chan ruleJob, 64), now: time.Now}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var rules []Rule
	if err == nil {
		if err = json.Unmarshal(data, &rules); err != nil {
			return nil, err
		}
	}
	if len(rules) > 64 {
		return nil, errors.New("規則最多 64 條")
	}
	now := e.now()
	for _, r := range rules {
		if r.ID == "" {
			return nil, errors.New("規則缺少 ID")
		}
		if _, ok := e.rules[r.ID]; ok {
			return nil, errors.New("規則 ID 重複")
		}
		if err := validateRule(r); err != nil {
			return nil, err
		}
		e.rules[r.ID] = r
		e.runtime[r.ID] = freshRuntime(now, 1)
		e.runtime[r.ID].CooldownUntil = r.LastTriggered.Add(time.Duration(r.CooldownSeconds) * time.Second)
	}
	e.syncRoutes(c.RuleRoutes(), now)
	e.readyError = c.RuleReadiness()
	return e, nil
}
func (e *RuleEngine) saveLocked() error {
	rules := make([]Rule, 0, len(e.rules))
	for _, r := range e.rules {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	data, err := json.MarshalIndent(rules, "", "  ")
	if err == nil {
		err = os.MkdirAll(filepath.Dir(e.path), 0700)
	}
	if err == nil {
		var f *os.File
		f, err = os.CreateTemp(filepath.Dir(e.path), ".rules-*")
		if err == nil {
			name := f.Name()
			defer os.Remove(name)
			_, err = f.Write(data)
			if err == nil {
				err = f.Sync()
			}
			closeErr := f.Close()
			if err == nil {
				err = closeErr
			}
			if err == nil {
				err = os.Rename(name, e.path)
			}
			if err == nil {
				var dir *os.File
				dir, err = os.Open(filepath.Dir(e.path))
				if err == nil {
					err = dir.Sync()
					dir.Close()
				}
			}
		}
	}
	if err != nil {
		e.persistenceError = err.Error()
	} else {
		e.persistenceError = ""
	}
	return err
}
func (e *RuleEngine) Upsert(id string, r Rule) (Rule, error) {
	if err := validateRule(r); err != nil {
		return Rule{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if id == "" {
		if len(e.rules) >= 64 {
			return Rule{}, errors.New("規則最多 64 條")
		}
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return Rule{}, err
		}
		id = hex.EncodeToString(b[:])
	} else if _, ok := e.rules[id]; !ok {
		return Rule{}, errors.New("規則不存在")
	}
	old, exists := e.rules[id]
	oldRuntime := e.runtime[id]
	if exists && (oldRuntime.Busy || oldRuntime.RouteID != "") {
		return Rule{}, errors.New("請先停用規則並等待路由撤回，再編輯")
	}
	r.ID = id
	r.LastTriggered = old.LastTriggered
	// Do not retain caller-owned slice/pointer storage.
	data, _ := json.Marshal(r)
	var detached Rule
	_ = json.Unmarshal(data, &detached)
	r = detached
	e.rules[id] = r
	if err := e.saveLocked(); err != nil {
		if exists {
			e.rules[id] = old
		} else {
			delete(e.rules, id)
		}
		return Rule{}, err
	}
	gen := uint64(1)
	if oldRuntime != nil {
		gen = oldRuntime.Generation + 1
	}
	e.runtime[id] = freshRuntime(e.now(), gen)
	e.runtime[id].CooldownUntil = r.LastTriggered.Add(time.Duration(r.CooldownSeconds) * time.Second)
	return r, nil
}
func (e *RuleEngine) Enable(id string, enabled bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.rules[id]
	if !ok {
		return errors.New("規則不存在")
	}
	old := r
	r.Enabled = enabled
	e.rules[id] = r
	if err := e.saveLocked(); err != nil {
		e.rules[id] = old
		return err
	}
	rt := e.runtime[id]
	rt.Generation++
	rt.HighSince = time.Time{}
	rt.LowSince = time.Time{}
	rt.Started = e.now()
	rt.Buckets = map[int64]float64{}
	return nil
}
func (e *RuleEngine) Delete(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.rules[id]
	if !ok {
		return errors.New("規則不存在")
	}
	rt := e.runtime[id]
	if rt.Busy || rt.RouteID != "" {
		return errors.New("請先停用規則並等待路由撤回，再刪除")
	}
	delete(e.rules, id)
	if err := e.saveLocked(); err != nil {
		e.rules[id] = r
		return err
	}
	delete(e.runtime, id)
	return nil
}
func (e *RuleEngine) Snapshot() any {
	e.mu.Lock()
	defer e.mu.Unlock()
	rows := []RuleView{}
	for id, r := range e.rules {
		rt := *e.runtime[id]
		rt.Buckets = nil
		rows = append(rows, RuleView{r, rt})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	data, _ := json.Marshal(struct {
		Rules   []RuleView `json:"rules"`
		Dropped uint64     `json:"dropped"`
		Error   string     `json:"persistence_error,omitempty"`
	}{rows, e.dropped.Load(), e.persistenceError})
	return json.RawMessage(data)
}
func (e *RuleEngine) Preview(id string, value float64) (any, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return nil, errors.New("測試數值需為非負有限數")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.rules[id]
	if !ok {
		return nil, errors.New("規則不存在")
	}
	return struct {
		Matched   bool         `json:"matched"`
		Value     float64      `json:"value"`
		Threshold float64      `json:"threshold"`
		Route     RouteRequest `json:"route"`
		Message   string       `json:"message"`
	}{value >= r.Threshold, value, r.Threshold, r.Route, "單值試算，不發送路由；實際觸發仍需滿足視窗、持續時間與資料新鮮度。"}, nil
}
func (e *RuleEngine) Observe(f RuleFlow) {
	select {
	case e.incoming <- f:
	default:
		e.dropped.Add(1)
	}
}
func (e *RuleEngine) consume(f RuleFlow, now time.Time) {
	if f.Received.IsZero() || now.Sub(f.Received) > time.Second || f.Received.After(now.Add(time.Second)) {
		e.dropped.Add(1)
		return
	}
	if math.IsNaN(f.Bytes) || math.IsNaN(f.Packets) || math.IsInf(f.Bytes, 0) || math.IsInf(f.Packets, 0) || f.Bytes < 0 || f.Packets < 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, r := range e.rules {
		if !r.Enabled || r.Source != f.Source {
			continue
		}
		index := f.InIf
		if r.Direction == "OUT" {
			index = f.OutIf
		}
		if r.InterfaceKey != "" && r.InterfaceKey != f.Source+"@"+f.Exporter+"@"+strconv.FormatUint(uint64(index), 10) {
			continue
		}
		rt := e.runtime[id]
		rt.LastTraffic = f.Received
		if r.Protocol != "any" && r.Protocol != f.Protocol {
			continue
		}
		prefix, _ := netip.ParsePrefix(r.Destination)
		if !prefix.Contains(f.Destination.Unmap()) {
			continue
		}
		if r.TCPFlags != nil && (!f.Flags.Known || f.Flags.Mask != *r.TCPFlags) {
			continue
		}
		amount := f.Packets
		if r.Metric == "bps" {
			amount = f.Bytes * 8
		}
		bucket := f.Received.UnixNano() / int64(100*time.Millisecond)
		rt.Buckets[bucket] += amount
	}
}
func (e *RuleEngine) evaluate(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	dropped := e.dropped.Load()
	if dropped != e.seenDropped {
		e.seenDropped = dropped
		for _, rt := range e.runtime {
			rt.Started = now
			rt.Buckets = map[int64]float64{}
			rt.HighSince = time.Time{}
			rt.LowSince = time.Time{}
		}
	}
	for id, r := range e.rules {
		rt := e.runtime[id]
		cut := now.UnixNano()/int64(100*time.Millisecond) - int64(r.WindowSeconds*10)
		sum := 0.0
		for t, v := range rt.Buckets {
			if t <= cut {
				delete(rt.Buckets, t)
			} else {
				sum += v
			}
		}
		rt.Value = sum / float64(r.WindowSeconds)
		if rt.Busy {
			rt.Phase = "pending"
			continue
		}
		if !r.Enabled {
			rt.Phase = "disabled"
			if rt.RouteID != "" {
				e.queueLocked(id, true, now)
			}
			continue
		}
		if rt.RouteID == "" && e.readyError != "" {
			rt.Phase = "disconnected"
			rt.HighSince = time.Time{}
			continue
		}
		if now.Sub(rt.Started) < time.Duration(r.WindowSeconds)*time.Second {
			rt.Phase = "warming"
			continue
		}
		staleAfter := time.Duration(r.WindowSeconds) * time.Second
		if staleAfter < 3*time.Second {
			staleAfter = 3 * time.Second
		}
		if rt.LastTraffic.IsZero() || now.Sub(rt.LastTraffic) > staleAfter {
			rt.Phase = "stale"
			rt.HighSince = time.Time{}
			rt.LowSince = time.Time{}
			continue
		}
		if rt.RouteID != "" {
			rt.Phase = "active"
			if rt.Value <= r.RecoveryThreshold {
				if rt.LowSince.IsZero() {
					rt.LowSince = now
					rt.LowObservation = rt.LastTraffic
				}
				rt.Phase = "recovering"
				if now.Sub(rt.LowSince) >= time.Duration(r.RecoverySeconds)*time.Second && rt.LastTraffic.After(rt.LowObservation) && now.Sub(rt.LastTraffic) <= time.Second {
					e.queueLocked(id, true, now)
				}
			} else {
				rt.LowSince = time.Time{}
			}
			continue
		}
		if now.Before(rt.CooldownUntil) {
			rt.Phase = "cooldown"
			rt.HighSince = time.Time{}
			continue
		}
		rt.Phase = "watching"
		if rt.Value >= r.Threshold {
			if rt.HighSince.IsZero() {
				rt.HighSince = now
			}
			rt.Phase = "holding"
			if now.Sub(rt.HighSince) >= time.Duration(r.HoldSeconds)*time.Second {
				e.queueLocked(id, false, now)
			}
		} else {
			rt.HighSince = time.Time{}
		}
	}
}
func (e *RuleEngine) queueLocked(id string, withdraw bool, now time.Time) {
	rt := e.runtime[id]
	if now.Before(rt.CooldownUntil) && withdraw && rt.Error != "" {
		return
	}
	if !withdraw {
		old := e.rules[id]
		r := old
		r.LastTriggered = now
		e.rules[id] = r
		if err := e.saveLocked(); err != nil {
			e.rules[id] = old
			rt.Error = err.Error()
			rt.Phase = "error"
			rt.CooldownUntil = now.Add(5 * time.Second)
			return
		}
	}
	job := ruleJob{id, rt.Generation, withdraw, rt.RouteID}
	select {
	case e.jobs <- job:
		rt.Busy = true
		rt.Phase = "pending"
	default:
		rt.Error = "動作佇列已滿"
		rt.CooldownUntil = now.Add(5 * time.Second)
		rt.Phase = "error"
	}
}
func (e *RuleEngine) syncRoutes(routes map[string]Route, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, rt := range e.runtime {
		route, ok := routes[id]
		if ok && !terminal(route.State) {
			rt.RouteID = route.ID
			rt.RouteState = route.State
			continue
		}
		if rt.RouteID != "" {
			rt.RouteID = ""
			rt.RouteState = ""
			rt.HighSince = time.Time{}
			rt.LowSince = time.Time{}
			rt.CooldownUntil = now.Add(time.Duration(e.rules[id].CooldownSeconds) * time.Second)
		}
	}
}
func (e *RuleEngine) execute(job ruleJob) {
	e.mu.Lock()
	r, ok := e.rules[job.ID]
	rt := e.runtime[job.ID]
	if !ok || rt.Generation != job.Generation || (!job.Withdraw && !r.Enabled) {
		if rt != nil {
			rt.Busy = false
		}
		e.mu.Unlock()
		return
	}
	if !job.Withdraw && (e.now().Sub(r.LastTriggered) > time.Second || rt.Value < r.Threshold || e.dropped.Load() != e.seenDropped) {
		rt.Busy = false
		rt.HighSince = time.Time{}
		rt.CooldownUntil = e.now().Add(time.Second)
		e.mu.Unlock()
		return
	}
	req := r.Route
	req.Note = "規則：" + r.Name
	e.mu.Unlock()
	var err error
	if job.Withdraw {
		err = e.control.Withdraw(job.RouteID)
	} else {
		_, err = e.control.AnnounceRule(req, r.ID)
	}
	routes := e.control.RuleRoutes()
	now := e.now()
	e.syncRoutes(routes, now)
	e.mu.Lock()
	defer e.mu.Unlock()
	rt = e.runtime[job.ID]
	if rt == nil {
		return
	}
	rt.Busy = false
	if err != nil {
		rt.Error = err.Error()
		rt.Phase = "error"
		rt.CooldownUntil = now.Add(time.Duration(r.CooldownSeconds) * time.Second)
	} else {
		rt.Error = ""
	}
}
func (e *RuleEngine) Run(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case job := <-e.jobs:
				e.execute(job)
			case <-ticker.C:
				e.syncRoutes(e.control.RuleRoutes(), e.now())
				ready := e.control.RuleReadiness()
				e.mu.Lock()
				e.readyError = ready
				e.mu.Unlock()
			}
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-e.incoming:
			now := e.now()
			e.consume(f, now)
		case now := <-ticker.C:
			e.evaluate(now)
		}
	}
}

func ruleError(err error) error { return fmt.Errorf("規則：%w", err) }

func (e *RuleEngine) AnyEnabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range e.rules {
		if r.Enabled {
			return true
		}
	}
	return false
}
