package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"
)

type ControlConfig struct {
	Mode            string   `json:"mode"`
	Endpoint        string   `json:"endpoint"`
	AllowedPrefixes []string `json:"allowed_prefixes"`
}
type RouteRequest struct {
	Prefix      string   `json:"prefix"`
	NextHop     string   `json:"next_hop"`
	Communities []string `json:"communities"`
	TTL         int      `json:"ttl"`
	Note        string   `json:"note"`
}
type Route struct {
	RouteRequest
	RuleID     string    `json:"rule_id,omitempty"`
	ID         string    `json:"id"`
	Identifier uint32    `json:"identifier"`
	UUID       []byte    `json:"uuid,omitempty"`
	Mode       string    `json:"mode"`
	State      string    `json:"state"`
	Error      string    `json:"error,omitempty"`
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires"`
}
type Event struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	Prefix string    `json:"prefix"`
	Mode   string    `json:"mode"`
	Detail string    `json:"detail"`
}
type ControlState struct {
	Config ControlConfig `json:"config"`
	Routes []*Route      `json:"routes"`
	Events []Event       `json:"events"`
}
type Controller struct {
	requireLive      bool
	mu               sync.Mutex
	state            ControlState
	path             string
	backend          Backend
	factory          func(string) (Backend, error)
	bgp              BGPView
	persistenceError string
}

func newController(path string) (*Controller, error) {
	c := &Controller{path: path, factory: connectBGP, state: ControlState{Config: ControlConfig{Mode: "simulation", Endpoint: "127.0.0.1:50051", AllowedPrefixes: []string{}}, Routes: []*Route{}, Events: []Event{}}}
	data, e := os.ReadFile(path)
	if e == nil {
		if e = json.Unmarshal(data, &c.state); e != nil {
			return nil, fmt.Errorf("讀取控制狀態：%w", e)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if e = validateConfig(c.state.Config); e != nil {
		return nil, e
	}
	if c.state.Config.Mode == "live" {
		c.backend, e = c.factory(c.state.Config.Endpoint)
		if e != nil {
			return nil, e
		}
	}
	if e = c.save(); e != nil {
		return nil, e
	}
	return c, nil
}
func validateConfig(c ControlConfig) error {
	if c.Mode != "simulation" && c.Mode != "live" && c.Mode != "unconfigured" {
		return errors.New("模式需為 simulation、unconfigured 或 live")
	}
	host, port, e := net.SplitHostPort(c.Endpoint)
	if e != nil || host == "" {
		return errors.New("GoBGP 位址需為 host:port")
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return errors.New("GoBGP 連接埠無效")
	}
	if len(c.AllowedPrefixes) > 64 {
		return errors.New("允許網段最多 64 組")
	}
	for _, s := range c.AllowedPrefixes {
		p, e := netip.ParsePrefix(s)
		if e != nil || p != p.Masked() || p.Bits() == 0 || p.Addr().Is4In6() {
			return fmt.Errorf("允許網段必須是非預設路由的標準 CIDR：%s", s)
		}
	}
	if c.Mode == "live" && len(c.AllowedPrefixes) == 0 {
		return errors.New("實際模式需先設定允許網段")
	}
	return nil
}
func validateRoute(r RouteRequest, c ControlConfig) error {
	p, e := netip.ParsePrefix(r.Prefix)
	if e != nil || p != p.Masked() || p.Bits() == 0 || p.Addr().Is4In6() {
		return errors.New("目的網段需為標準 CIDR，且不可為預設路由")
	}
	if p.Addr().IsMulticast() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() || p.Addr().IsUnspecified() {
		return errors.New("目的網段不是可用的單播網段")
	}
	nh, e := netip.ParseAddr(r.NextHop)
	if e != nil || nh.Is4() != p.Addr().Is4() || nh.IsUnspecified() || nh.IsMulticast() || nh.Is4In6() || nh.Zone() != "" {
		return errors.New("Next hop 必須是與目的網段同版本的有效單播 IP")
	}
	allowed := false
	for _, s := range c.AllowedPrefixes {
		a, _ := netip.ParsePrefix(s)
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			allowed = true
			break
		}
	}
	if !allowed {
		return errors.New("目的網段不在允許操作的網段內，請先設定允許網段")
	}
	if _, _, e = communities(r.Communities); e != nil {
		return e
	}
	if r.TTL < 1 || r.TTL > 86400 {
		return errors.New("到期時間需介於 1–86400 秒")
	}
	if len(r.Note) > 256 {
		return errors.New("備註最多 256 bytes")
	}
	return nil
}

// The intent is fsynced before any BGP mutation. On restart, pending operations
// are resolved against GoBGP using a persisted path identifier and returned UUID.
func (c *Controller) save() (err error) {
	defer func() {
		if err != nil {
			c.persistenceError = err.Error()
		}
	}()
	data, e := json.MarshalIndent(c.state, "", "  ")
	if e != nil {
		return e
	}
	dir := filepath.Dir(c.path)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".control-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(data); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(name, c.path)
	}
	if e == nil {
		var d *os.File
		d, e = os.Open(dir)
		if e == nil {
			e = d.Sync()
			d.Close()
		}
	}
	if e != nil {
		c.persistenceError = e.Error()
	} else {
		c.persistenceError = ""
	}
	return e
}
func (c *Controller) event(action string, r *Route, detail string) {
	ev := Event{Time: time.Now().UTC(), Action: action, Mode: c.state.Config.Mode, Detail: detail}
	if r != nil {
		ev.Prefix = r.Prefix
		ev.Mode = r.Mode
	}
	c.state.Events = append(c.state.Events, ev)
	if len(c.state.Events) > 500 {
		c.state.Events = c.state.Events[len(c.state.Events)-500:]
	}
}
func terminal(state string) bool {
	return state == "withdrawn" || state == "absent" || state == "failed"
}
func (c *Controller) Configure(cfg ControlConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.requireLive && cfg.Mode != "live" {
		return errors.New("請設定正式 GoBGP 連線")
	}
	if e := validateConfig(cfg); e != nil {
		return e
	}
	for _, r := range c.state.Routes {
		if !terminal(r.State) {
			return errors.New("請先撤回所有操作中的路由，再修改連線或允許網段")
		}
	}
	var b Backend
	var e error
	if cfg.Mode == "live" {
		b, e = c.factory(cfg.Endpoint)
		if e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if _, e = b.Status(ctx); e != nil {
			b.Close()
			return fmt.Errorf("GoBGP 連線失敗：%w", e)
		}
	}
	old := c.state.Config
	c.state.Config = cfg
	if e = c.save(); e != nil {
		c.state.Config = old
		if b != nil {
			b.Close()
		}
		return e
	}
	if c.backend != nil {
		c.backend.Close()
	}
	c.backend = b
	c.bgp = BGPView{}
	c.event("settings", nil, "已更新控制設定")
	return c.save()
}
func (c *Controller) Announce(req RouteRequest) (*Route, error) {
	return c.announce(req, "")
}

// Rule actions always use the real, configured GoBGP backend.
func (c *Controller) AnnounceRule(req RouteRequest, ruleID string) (*Route, error) {
	if ruleID == "" {
		return nil, errors.New("規則 ID 不可空白")
	}
	return c.announce(req, ruleID)
}
func (c *Controller) announce(req RouteRequest, ruleID string) (*Route, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cfg := c.state.Config
	if cfg.Mode == "unconfigured" || (c.requireLive && cfg.Mode != "live") {
		return nil, errors.New("尚未設定 Core／GoBGP 正式連線")
	}
	if ruleID != "" {
		for _, existing := range c.state.Routes {
			if existing.RuleID == ruleID && !terminal(existing.State) {
				cp := *existing
				return &cp, nil
			}
		}
		if cfg.Mode != "live" {
			return nil, errors.New("尚未設定 Core／GoBGP 正式連線")
		}
	}
	if e := validateRoute(req, cfg); e != nil {
		return nil, e
	}
	active := 0
	for _, r := range c.state.Routes {
		if !terminal(r.State) {
			active++
			if r.Prefix == req.Prefix {
				return nil, errors.New("此網段已有操作中的路由，請先撤回")
			}
		}
	}
	if active >= 128 {
		return nil, errors.New("同時最多管理 128 條路由")
	}
	var buf [16]byte
	if _, e := rand.Read(buf[:]); e != nil {
		return nil, e
	}
	now := time.Now().UTC()
	r := &Route{RouteRequest: req, RuleID: ruleID, ID: hex.EncodeToString(buf[:]), Identifier: binary.BigEndian.Uint32(buf[:4]) | 0x80000000, Mode: cfg.Mode, State: "pending", Created: now, Expires: now.Add(time.Duration(req.TTL) * time.Second)}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if r.Mode == "live" {
		paths, e := c.backend.Paths(ctx, r.Prefix)
		if e != nil {
			return nil, e
		}
		for _, p := range paths {
			if p.GetNeighborIp() == "" || p.GetNeighborIp() == "<nil>" || len(p.GetUuid()) > 0 {
				return nil, errors.New("GoBGP 已存在此網段的本地路由，請先由原管理者處理")
			}
		}
	}
	// Bound retained completed route records; the event history is bounded separately.
	if len(c.state.Routes) >= 500 {
		c.state.Routes = slices.DeleteFunc(c.state.Routes, func(x *Route) bool { return terminal(x.State) })
	}
	c.state.Routes = append(c.state.Routes, r)
	if e := c.save(); e != nil {
		c.state.Routes = c.state.Routes[:len(c.state.Routes)-1]
		return nil, e
	}
	if r.Mode == "simulation" {
		r.State = "simulated"
		c.event("announce", r, "模擬宣告")
	} else {
		uuid, e := c.backend.Add(ctx, r)
		if e != nil {
			r.Error = e.Error()
			c.event("announce_pending", r, e.Error())
			_ = c.save()
			return nil, fmt.Errorf("宣告結果待確認，請查看路由狀態：%w", e)
		}
		r.UUID = uuid
		r.State = "active"
		c.event("announce", r, "已加入 GoBGP 本地 RIB；對端是否採用請確認鄰居政策")
	}
	if e := c.save(); e != nil {
		return nil, fmt.Errorf("操作已執行，但狀態儲存失敗：%w", e)
	}
	copy := *r
	return &copy, nil
}
func (c *Controller) Withdraw(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.state.Routes {
		if r.ID == id {
			return c.withdraw(r)
		}
	}
	return errors.New("找不到路由")
}
func (c *Controller) withdraw(r *Route) error {
	if terminal(r.State) {
		return nil
	}
	old := r.State
	r.State = "withdrawing"
	if e := c.save(); e != nil {
		r.State = old
		return e
	}
	if r.Mode == "simulation" {
		r.State = "withdrawn"
		r.Error = ""
		c.event("withdraw", r, "模擬撤回")
		return c.save()
	}
	e := c.reconcile(r)
	saveErr := c.save()
	if e != nil {
		return e
	}
	return saveErr
}
func (c *Controller) reconcile(r *Route) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	paths, e := c.backend.Paths(ctx, r.Prefix)
	if e != nil {
		r.Error = e.Error()
		return e
	}
	found := false
	var foundUUID []byte
	for _, p := range paths {
		// Some GoBGP versions omit UUID in ListPath. Identifier is also scoped to
		// this exact prefix and local origin; a foreign/learned path never matches.
		local := p.GetNeighborIp() == "" || p.GetNeighborIp() == "<nil>"
		match := local && r.Identifier != 0 && p.GetIdentifier() == r.Identifier
		if len(r.UUID) > 0 && len(p.GetUuid()) > 0 {
			match = match && slices.Equal(r.UUID, p.GetUuid())
		}
		if match {
			found = true
			foundUUID = p.GetUuid()
			break
		}
	}
	if !found {
		previous := r.State
		if (previous == "pending" || (previous == "withdrawing" && len(r.UUID) == 0)) && time.Since(r.Created) < 30*time.Second {
			return nil
		}
		if previous == "withdrawing" {
			r.State = "withdrawn"
		} else {
			r.State = "absent"
		}
		r.Error = ""
		c.event(r.State, r, "已確認 GoBGP 沒有此操作所建立的路由")
		return nil
	}
	if len(foundUUID) > 0 {
		r.UUID = foundUUID
	}
	if r.State == "withdrawing" {
		if e = c.backend.Delete(ctx, r); e != nil {
			r.Error = e.Error()
			return e
		}
		r.State = "withdrawn"
		r.Error = ""
		c.event("withdraw", r, "已從 GoBGP 撤回")
	} else {
		if r.State == "pending" {
			c.event("recovered", r, "已確認先前宣告成功")
		}
		r.State = "active"
		r.Error = ""
	}
	return nil
}
func (c *Controller) Tick(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.backend != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		v, e := c.backend.Status(ctx)
		cancel()
		if e != nil {
			v.Error = e.Error()
		}
		c.bgp = v
		if e != nil {
			return
		}
	}
	dirty := false
	for _, r := range c.state.Routes {
		if terminal(r.State) {
			continue
		}
		if !now.Before(r.Expires) && r.State != "withdrawing" {
			_ = c.withdraw(r)
			dirty = true
			continue
		}
		if r.Mode == "live" {
			before := r.State
			errBefore := r.Error
			_ = c.reconcile(r)
			dirty = dirty || before != r.State || errBefore != r.Error
		}
	}
	if dirty || c.persistenceError != "" {
		_ = c.save()
	}
}
func (c *Controller) Run(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	c.Tick(time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			c.Tick(now)
		}
	}
}
func (c *Controller) Snapshot() any {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Marshal under lock so callers cannot race with lifecycle transitions.
	data, _ := json.Marshal(struct {
		ControlState
		BGP              BGPView `json:"bgp"`
		PersistenceError string  `json:"persistence_error,omitempty"`
	}{c.state, c.bgp, c.persistenceError})
	return json.RawMessage(data)
}

// Rules only reconcile routes they own. Called from the action worker, never
// the flow receiver, because the controller may be waiting on gRPC.
func (c *Controller) RuleRoutes() map[string]Route {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := map[string]Route{}
	for _, r := range c.state.Routes {
		if r.RuleID != "" {
			cp := *r
			cp.Communities = append([]string{}, r.Communities...)
			result[r.RuleID] = cp
		}
	}
	return result
}

func (c *Controller) RuleReadiness() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.Config.Mode != "live" || c.backend == nil {
		return "尚未設定 Core／GoBGP 正式連線"
	}
	if !c.bgp.Connected {
		return "GoBGP 尚未連線"
	}
	return ""
}

func (c *Controller) RequireLive() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requireLive = true
	if c.state.Config.Mode == "simulation" {
		c.state.Config.Mode = "unconfigured"
		return c.save()
	}
	return nil
}
