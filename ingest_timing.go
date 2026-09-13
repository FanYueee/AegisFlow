package main

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// These diagnostics describe decoded exporter timestamps, not local processing
// latency. Exporter clock skew and timestamp resolution affect report age.
// The decoder may substitute export time when flow timestamps are absent;
// a zero-duration record therefore cannot establish a measurement interval.
var (
	flowReportDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "flow_report_duration_seconds", Help: "Positive interval between decoded flow start and end timestamps; not a guaranteed exporter flush interval.",
		Buckets: []float64{.1, .5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 900, 1800, 3600},
	}, []string{"source"})
	flowReportAge = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "flow_report_age_seconds", Help: "Nonnegative age of decoded flow end at recording time, including exporter delay, transport, decoding, clock skew and timestamp resolution. Not local processing latency.",
		Buckets: []float64{.1, .5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 900, 1800, 3600},
	}, []string{"source"})
	flowTimestampRecords = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flow_report_timestamp_records_total", Help: "Flow timestamp diagnostics; zero_duration cannot establish an interval, future may indicate exporter clock skew.",
	}, []string{"source", "status"})
	flowLastReceived = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "flow_last_received_seconds", Help: "Collector timestamp of last decoded record. Missing traffic must not be interpreted as recovery.",
	}, []string{"source"})
)

func init() {
	prometheus.MustRegister(flowReportDuration, flowReportAge, flowTimestampRecords, flowLastReceived)
}

func reportTiming(start, end uint64, now time.Time) (duration, age float64, status string) {
	if start == 0 || end == 0 {
		return 0, 0, "missing"
	}
	if end < start {
		return 0, 0, "reversed"
	}
	if now.UnixNano() < 0 || end > uint64(now.UnixNano()) {
		return 0, 0, "future"
	}
	duration = float64(end-start) / 1e9
	age = float64(uint64(now.UnixNano())-end) / 1e9
	if end == start {
		return duration, age, "zero_duration"
	}
	return duration, age, "valid"
}

func recordIngestTiming(source string, start, end uint64, now time.Time) {
	flowLastReceived.WithLabelValues(source).Set(float64(now.UnixNano()) / 1e9)
	if source != "netflow9" && source != "ipfix" {
		return
	}
	duration, age, status := reportTiming(start, end, now)
	flowTimestampRecords.WithLabelValues(source, status).Inc()
	if status == "valid" {
		flowReportDuration.WithLabelValues(source).Observe(duration)
	}
	if status == "valid" || status == "zero_duration" {
		flowReportAge.WithLabelValues(source).Observe(age)
	}
}
