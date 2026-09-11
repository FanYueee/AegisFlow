package main

import (
	"log"
	"net"
	"os"
	"strconv"

	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/prometheus/client_golang/prometheus"
)

var debugFlows = os.Getenv("AEGISFLOW_DEBUG") != ""

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
	case 47:
		return "gre"
	case 58:
		return "icmpv6"
	default:
		return strconv.FormatUint(uint64(proto), 10)
	}
}

// RecordFlow updates Prometheus metrics from a single decoded flow message.
// sourceType is a short label such as "sflow", "netflow9", or "ipfix".
// fallbackSampler is used as the sampler address when the message itself
// doesn't carry one (e.g. NetFlow v9/IPFIX, decoded without a producer.ProduceArgs).
// fallbackSamplingRate is applied when the message doesn't report its own
// sampling rate — e.g. MikroTik's packet-sampling doesn't announce its ratio
// over the protocol, so it has to be supplied out of band.
func RecordFlow(msg interface{}, sourceType string, fallbackSampler net.IP, fallbackSamplingRate uint64) {
	pm, ok := msg.(*protoproducer.ProtoProducerMessage)
	if !ok {
		return
	}

	samplerAddr := net.IP(pm.SamplerAddress)
	if samplerAddr == nil {
		samplerAddr = fallbackSampler
	}

	inIf := strconv.FormatUint(uint64(pm.InIf), 10)
	outIf := strconv.FormatUint(uint64(pm.OutIf), 10)
	proto := protoName(pm.Proto)
	srcAs := strconv.FormatUint(uint64(pm.SrcAs), 10)
	dstAs := strconv.FormatUint(uint64(pm.DstAs), 10)

	// Each sample represents one packet out of every SamplingRate packets seen
	// by the exporter; multiply back up to estimate real traffic volume.
	samplingRate := pm.SamplingRate
	if samplingRate == 0 {
		samplingRate = fallbackSamplingRate
	}

	if debugFlows {
		log.Printf("debug flow: type=%s in_if=%s out_if=%s proto=%s bytes=%d packets=%d sampling_rate=%d src=%s dst=%s",
			sourceType, inIf, outIf, proto, pm.Bytes, pm.Packets, pm.SamplingRate, net.IP(pm.SrcAddr), net.IP(pm.DstAddr))
	}

	flowBytesTotal.WithLabelValues(sourceType, inIf, outIf, proto, srcAs, dstAs).Add(float64(pm.Bytes) * float64(samplingRate))
	flowPacketsTotal.WithLabelValues(sourceType, inIf, outIf, proto, srcAs, dstAs).Add(float64(pm.Packets) * float64(samplingRate))
	flowSamplesTotal.WithLabelValues(sourceType, samplerAddr.String()).Inc()
}
