package main

import (
	"fmt"
	"math"
)

// Each NetFlow/IPFIX record contributes all of its packets to the bucket of
// bytes/packets. This is a distribution of record means, not individual lengths.
// Bound label cardinality while preserving larger values in an overflow bucket.
const packetSizeOverflow = uint32(65600)

func meanPacketSizeBucket(bytes, packets float64) (uint32, bool) {
	if packets <= 0 || bytes <= 0 || math.IsNaN(bytes) || math.IsNaN(packets) || math.IsInf(bytes, 0) || math.IsInf(packets, 0) {
		return 0, false
	}
	mean := bytes / packets
	if mean >= float64(packetSizeOverflow) {
		return packetSizeOverflow, true
	}
	return uint32(mean/100) * 100, true
}
func packetSizeLabel(bucket uint32) string {
	if bucket == packetSizeOverflow {
		return "≥65600 Bytes"
	}
	return fmt.Sprintf("%d–<%d Bytes", bucket, bucket+100)
}
