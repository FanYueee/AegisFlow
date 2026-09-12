package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"
)

// A separate, lightweight scrape endpoint exposes completed one-second windows.
// Flow-scope values are arrival-time accounting of exported flow totals, never
// a reconstruction of packet timings. Packet-scope values are sampled estimates.
type realtimeCollector struct {
	observer                *Observer
	mu                      sync.Mutex
	seen                    map[flagKey]time.Time
	bps, pps, end, duration *prometheus.Desc
}

func newRealtimeCollector(o *Observer) *realtimeCollector {
	labels := []string{"source", "scope", "combination", "classification"}
	return &realtimeCollector{observer: o, seen: map[flagKey]time.Time{},
		bps:      prometheus.NewDesc("flow_tcp_flag_combination_current_bps", "Bytes received in the last completed collection window, converted to bits per second. Flow scope is export-arrival accounting, not packet-time bandwidth.", labels, nil),
		pps:      prometheus.NewDesc("flow_tcp_flag_combination_current_pps", "Sampling-adjusted packets received in the last completed collection window, per second. Flow scope is export-arrival accounting, not per-packet wire timing.", labels, nil),
		end:      prometheus.NewDesc("aegisflow_current_window_end_seconds", "End timestamp of the latest completed collection window.", nil, nil),
		duration: prometheus.NewDesc("aegisflow_current_window_duration_seconds", "Actual duration of the latest completed collection window.", nil, nil)}
}
func (c *realtimeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.bps
	ch <- c.pps
	ch <- c.end
	ch <- c.duration
}
func (c *realtimeCollector) Collect(ch chan<- prometheus.Metric) {
	c.observer.mu.Lock()
	values := map[flagKey]Rates{}
	end := c.observer.timeStart
	seconds := 0.0
	if len(c.observer.recent) > 0 {
		bucket := c.observer.recent[len(c.observer.recent)-1]
		seconds = bucket.duration
		for k, v := range bucket.flags {
			values[k] = divide(v, seconds)
		}
	}
	c.observer.mu.Unlock()
	if seconds <= 0 {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.end, prometheus.GaugeValue, float64(end.UnixNano())/1e9)
	ch <- prometheus.MustNewConstMetric(c.duration, prometheus.GaugeValue, seconds)
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range values {
		c.seen[k] = end
	}
	for k, last := range c.seen {
		if end.Sub(last) > 5*time.Minute {
			delete(c.seen, k)
			continue
		}
		info := classifyTCPFlags(k.Mask, flagScope(k.Source), k.Known)
		labels := []string{k.Source, flagScope(k.Source), info.Combination, info.Verdict}
		r := values[k] // Explicit zero for idle combinations; no stale last value.
		ch <- prometheus.MustNewConstMetric(c.bps, prometheus.GaugeValue, r.BPS, labels...)
		ch <- prometheus.MustNewConstMetric(c.pps, prometheus.GaugeValue, r.PPS, labels...)
	}
}
