package main

import (
	"net"
	"sort"
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var interfaceLabels = []string{"source", "exporter", "interface", "interface_key", "direction", "proto"}
var (
	interfaceBytes       = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "flow_interface_bytes_total", Help: "Sampling-adjusted bytes per exporter interface and direction. IN and OUT are distinct observations, never a deduplicated combined total."}, interfaceLabels)
	interfacePackets     = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "flow_interface_packets_total", Help: "Sampling-adjusted packets per exporter interface and direction."}, interfaceLabels)
	interfaceRecords     = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "flow_interface_records_total", Help: "Decoded records per exporter interface and direction, without sampling multiplication."}, interfaceLabels)
	interfaceDstBytes    = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "flow_interface_dst_bytes_total", Help: "Sampling-adjusted destination bytes per interface and direction."}, append(append([]string{}, interfaceLabels...), "dst_cidr"))
	interfaceDstPackets  = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "flow_interface_dst_packets_total", Help: "Sampling-adjusted destination packets per interface and direction."}, append(append([]string{}, interfaceLabels...), "dst_cidr"))
	interfaceFlagLabels  = []string{"source", "exporter", "interface", "interface_key", "direction", "scope", "combination", "classification"}
	interfaceFlagBytes   = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "flow_interface_tcp_combination_bytes_total", Help: "Whole TCP flag combination bytes per interface direction. NetFlow is a flow union, sFlow is a packet sample."}, interfaceFlagLabels)
	interfaceFlagPackets = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "flow_interface_tcp_combination_packets_total", Help: "Whole TCP flag combination packets per interface direction. A record counts once per direction, never once per bit."}, interfaceFlagLabels)
	interfaceSizePackets = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "flow_interface_mean_packet_size_packets_total", Help: "Sampling-adjusted packet counts grouped by each record's mean bytes per packet in non-overlapping 100-byte buckets. Not individual NetFlow packet lengths. Zero or missing sizes are unknown."}, append(append([]string{}, interfaceLabels...), "size_range"))
	interfaceCatalog     = struct {
		sync.RWMutex
		entries map[string]InterfaceInfo
	}{entries: map[string]InterfaceInfo{}}
)

type InterfaceInfo struct {
	Key      string `json:"key"`
	Exporter string `json:"exporter"`
	Source   string `json:"source"`
	Index    string `json:"index"`
}

func init() {
	prometheus.MustRegister(interfaceBytes, interfacePackets, interfaceRecords, interfaceDstBytes, interfaceDstPackets, interfaceFlagBytes, interfaceFlagPackets, interfaceSizePackets)
}
func knownInterfaces() []InterfaceInfo {
	interfaceCatalog.RLock()
	defer interfaceCatalog.RUnlock()
	rows := make([]InterfaceInfo, 0, len(interfaceCatalog.entries))
	for _, v := range interfaceCatalog.entries {
		rows = append(rows, v)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
	return rows
}
func recordInterfaces(source string, exporter net.IP, inIf, outIf uint32, proto, cidr string, flags TCPFlagObservation, bytes, packets float64) {
	address := exporter.String()
	if len(exporter) == 0 {
		address = "unknown"
	}
	sizeRange := "未知"
	if bucket, ok := meanPacketSizeBucket(bytes, packets); ok {
		sizeRange = packetSizeLabel(bucket)
	}
	for _, v := range []struct {
		index     uint32
		direction string
	}{{inIf, "IN"}, {outIf, "OUT"}} {
		index := strconv.FormatUint(uint64(v.index), 10)
		key := source + "@" + address + "@" + index
		interfaceCatalog.Lock()
		interfaceCatalog.entries[key] = InterfaceInfo{key, address, source, index}
		interfaceCatalog.Unlock()
		labels := []string{source, address, index, key, v.direction, proto}
		interfaceBytes.WithLabelValues(labels...).Add(bytes)
		interfacePackets.WithLabelValues(labels...).Add(packets)
		interfaceRecords.WithLabelValues(labels...).Inc()
		if packets > 0 {
			sl := append(append([]string{}, labels...), sizeRange)
			interfaceSizePackets.WithLabelValues(sl...).Add(packets)
		}
		if cidr != "" {
			dl := append(append([]string{}, labels...), cidr)
			interfaceDstBytes.WithLabelValues(dl...).Add(bytes)
			interfaceDstPackets.WithLabelValues(dl...).Add(packets)
		}
		if proto == "tcp" {
			scope := flagScope(source)
			f := classifyTCPFlags(flags.Mask, scope, flags.Known)
			fl := []string{source, address, index, key, v.direction, scope, f.Combination, f.Verdict}
			interfaceFlagBytes.WithLabelValues(fl...).Add(bytes)
			interfaceFlagPackets.WithLabelValues(fl...).Add(packets)
		}
	}
}
