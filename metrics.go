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

// dstCIDRPrefixV4/V6 control how destination addresses are bucketed into
// CIDRs before being used as a Prometheus label. A fixed prefix keeps
// cardinality bounded regardless of how many distinct destination IPs are
// actually seen.
var (
	dstCIDRPrefixV4 = 24
	dstCIDRPrefixV6 = 48
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

	flowDstCIDRBytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flow_dst_cidr_bytes_total",
		Help: "Total bytes seen per destination CIDR bucket.",
	}, []string{"dst_cidr"})

	flowDstCIDRPacketsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flow_dst_cidr_packets_total",
		Help: "Total packets seen per destination CIDR bucket.",
	}, []string{"dst_cidr"})

	flowTCPFlagBytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flow_tcp_flag_bytes_total",
		Help: "Total bytes seen per individual TCP flag (a packet with multiple flags set counts toward each).",
	}, []string{"flag"})

	flowTCPFlagPacketsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flow_tcp_flag_packets_total",
		Help: "Total packets seen per individual TCP flag (a packet with multiple flags set counts toward each).",
	}, []string{"flag"})
)

func init() {
	prometheus.MustRegister(
		flowBytesTotal, flowPacketsTotal, flowSamplesTotal,
		flowDstCIDRBytesTotal, flowDstCIDRPacketsTotal,
		flowTCPFlagBytesTotal, flowTCPFlagPacketsTotal,
	)
}

// protoName maps the IANA L4 protocol number to one of a fixed set of
// readable buckets, keeping Prometheus label cardinality at exactly 5 values.
func protoName(proto uint32) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 47:
		return "gre"
	case 1, 58:
		return "icmp"
	default:
		return "other"
	}
}

// tcpFlagBits lists the standard TCP flags in header bit order.
var tcpFlagBits = []struct {
	mask uint32
	name string
}{
	{0x01, "FIN"},
	{0x02, "SYN"},
	{0x04, "RST"},
	{0x08, "PSH"},
	{0x10, "ACK"},
	{0x20, "URG"},
	{0x40, "ECE"},
	{0x80, "CWR"},
}

// dstCIDR buckets an IP address down to a fixed-length prefix so it can be
// used as a Prometheus label without unbounded cardinality growth.
func dstCIDR(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		mask := net.CIDRMask(dstCIDRPrefixV4, 32)
		return ip4.Mask(mask).String() + "/" + strconv.Itoa(dstCIDRPrefixV4)
	}
	if ip16 := ip.To16(); ip16 != nil {
		mask := net.CIDRMask(dstCIDRPrefixV6, 128)
		return ip16.Mask(mask).String() + "/" + strconv.Itoa(dstCIDRPrefixV6)
	}
	return ""
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
	bytes := float64(pm.Bytes) * float64(samplingRate)
	packets := float64(pm.Packets) * float64(samplingRate)

	if debugFlows {
		log.Printf("debug flow: type=%s in_if=%s out_if=%s proto=%s bytes=%d packets=%d sampling_rate=%d src=%s dst=%s",
			sourceType, inIf, outIf, proto, pm.Bytes, pm.Packets, pm.SamplingRate, net.IP(pm.SrcAddr), net.IP(pm.DstAddr))
	}

	flowBytesTotal.WithLabelValues(sourceType, inIf, outIf, proto, srcAs, dstAs).Add(bytes)
	flowPacketsTotal.WithLabelValues(sourceType, inIf, outIf, proto, srcAs, dstAs).Add(packets)
	flowSamplesTotal.WithLabelValues(sourceType, samplerAddr.String()).Inc()

	if cidr := dstCIDR(net.IP(pm.DstAddr)); cidr != "" {
		flowDstCIDRBytesTotal.WithLabelValues(cidr).Add(bytes)
		flowDstCIDRPacketsTotal.WithLabelValues(cidr).Add(packets)
	}

	if proto == "tcp" {
		for _, f := range tcpFlagBits {
			if pm.TcpFlags&f.mask != 0 {
				flowTCPFlagBytesTotal.WithLabelValues(f.name).Add(bytes)
				flowTCPFlagPacketsTotal.WithLabelValues(f.name).Add(packets)
			}
		}
	}
}
