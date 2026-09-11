package main

import (
	"net"
	"strconv"

	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	flowBytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flow_bytes_total",
		Help: "Total bytes seen in flow samples, labeled by interface/proto/AS.",
	}, []string{"type", "in_if", "out_if", "proto", "src_as", "dst_as"})

	flowPacketsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flow_packets_total",
		Help: "Total packets seen in flow samples, labeled by interface/proto/AS.",
	}, []string{"type", "in_if", "out_if", "proto", "src_as", "dst_as"})

	flowSamplesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flow_samples_total",
		Help: "Total number of flow messages received, labeled by exporter and source type.",
	}, []string{"type", "sampler_address"})
)

func init() {
	prometheus.MustRegister(flowBytesTotal, flowPacketsTotal, flowSamplesTotal)
}

// protoName maps the IANA L4 protocol number to a short readable string.
// Only a small, fixed set is mapped to keep Prometheus label cardinality low;
// anything else falls back to its numeric string.
func protoName(proto uint32) string {
	switch proto {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return strconv.FormatUint(uint64(proto), 10)
	}
}

// RecordFlow updates Prometheus metrics from a single decoded flow message.
// sourceType is a short label such as "sflow", "netflow9", or "ipfix".
func RecordFlow(msg interface{}, sourceType string) {
	pm, ok := msg.(*protoproducer.ProtoProducerMessage)
	if !ok {
		return
	}

	inIf := strconv.FormatUint(uint64(pm.InIf), 10)
	outIf := strconv.FormatUint(uint64(pm.OutIf), 10)
	proto := protoName(pm.Proto)
	srcAs := strconv.FormatUint(uint64(pm.SrcAs), 10)
	dstAs := strconv.FormatUint(uint64(pm.DstAs), 10)

	flowBytesTotal.WithLabelValues(sourceType, inIf, outIf, proto, srcAs, dstAs).Add(float64(pm.Bytes))
	flowPacketsTotal.WithLabelValues(sourceType, inIf, outIf, proto, srcAs, dstAs).Add(float64(pm.Packets))
	flowSamplesTotal.WithLabelValues(sourceType, net.IP(pm.SamplerAddress).String()).Inc()
}
