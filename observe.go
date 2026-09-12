package main

import (
	"context"
	"sort"
	"sync"
	"time"
)

type Rates struct {
	BPS     float64 `json:"bps"`
	PPS     float64 `json:"pps"`
	Samples float64 `json:"samples"`
}
type TrafficRow struct {
	Name string `json:"name"`
	Rates
}
type TrafficPoint struct {
	Time time.Time `json:"time"`
	Rates
}
type TrafficView struct {
	Current       Rates          `json:"current"`
	LastFlow      time.Time      `json:"last_flow"`
	History       []TrafficPoint `json:"history"`
	Destinations  []TrafficRow   `json:"destinations"`
	Protocols     []TrafficRow   `json:"protocols"`
	Flags         []TrafficRow   `json:"flags"`
	Overflow      uint64         `json:"overflow"`
	WindowSeconds float64        `json:"window_seconds"`
}
type trafficBucket struct {
	duration                       float64
	total                          Rates
	destinations, protocols, flags map[string]Rates
}
type Observer struct {
	mu                  sync.Mutex
	bucket              trafficBucket
	recent              []trafficBucket
	history             []TrafficPoint
	lastFlow, timeStart time.Time
	overflow            uint64
}

func emptyBucket() trafficBucket {
	return trafficBucket{destinations: map[string]Rates{}, protocols: map[string]Rates{}, flags: map[string]Rates{}}
}
func newObserver() *Observer {
	return &Observer{bucket: emptyBucket(), timeStart: time.Now(), history: []TrafficPoint{}}
}
func addRates(a, b Rates) Rates { return Rates{a.BPS + b.BPS, a.PPS + b.PPS, a.Samples + b.Samples} }
func divide(a Rates, n float64) Rates {
	if n <= 0 {
		return Rates{}
	}
	return Rates{a.BPS / n, a.PPS / n, a.Samples / n}
}
func (o *Observer) Record(cidr, proto string, flags uint32, bytes, packets float64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lastFlow = time.Now()
	r := Rates{bytes * 8, packets, 1}
	o.bucket.total = addRates(o.bucket.total, r)
	o.bucket.protocols[proto] = addRates(o.bucket.protocols[proto], r)
	if cidr != "" {
		if _, ok := o.bucket.destinations[cidr]; ok || len(o.bucket.destinations) < 4096 {
			o.bucket.destinations[cidr] = addRates(o.bucket.destinations[cidr], r)
		} else {
			o.overflow++
		}
	}
	if proto == "tcp" {
		for _, f := range tcpFlagBits {
			if flags&f.mask != 0 {
				o.bucket.flags[f.name] = addRates(o.bucket.flags[f.name], r)
			}
		}
	}
}
func (o *Observer) rotate(now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.bucket.duration = now.Sub(o.timeStart).Seconds()
	o.timeStart = now
	o.recent = append(o.recent, o.bucket)
	if len(o.recent) > 5 {
		o.recent = o.recent[1:]
	}
	o.bucket = emptyBucket()
	r, d := o.current()
	o.history = append(o.history, TrafficPoint{now, divide(r, d)})
	if len(o.history) > 300 {
		o.history = o.history[1:]
	}
}
func (o *Observer) current() (Rates, float64) {
	var total Rates
	var d float64
	for _, b := range o.recent {
		total = addRates(total, b.total)
		d += b.duration
	}
	return total, d
}
func topRows(values map[string]Rates, seconds float64) []TrafficRow {
	rows := make([]TrafficRow, 0, len(values))
	for name, r := range values {
		rows = append(rows, TrafficRow{name, divide(r, seconds)})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].BPS == rows[j].BPS {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].BPS > rows[j].BPS
	})
	if len(rows) > 8 {
		rows = rows[:8]
	}
	return rows
}
func (o *Observer) Snapshot() TrafficView {
	o.mu.Lock()
	defer o.mu.Unlock()
	total, seconds := o.current()
	dst, protos, flags := map[string]Rates{}, map[string]Rates{}, map[string]Rates{}
	for _, b := range o.recent {
		for n, r := range b.destinations {
			dst[n] = addRates(dst[n], r)
		}
		for n, r := range b.protocols {
			protos[n] = addRates(protos[n], r)
		}
		for n, r := range b.flags {
			flags[n] = addRates(flags[n], r)
		}
	}
	return TrafficView{Current: divide(total, seconds), LastFlow: o.lastFlow, History: append([]TrafficPoint{}, o.history...), Destinations: topRows(dst, seconds), Protocols: topRows(protos, seconds), Flags: topRows(flags, seconds), Overflow: o.overflow, WindowSeconds: seconds}
}
func (o *Observer) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			o.rotate(now)
		}
	}
}
