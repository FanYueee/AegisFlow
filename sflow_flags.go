package main

import (
	"encoding/binary"
	"github.com/netsampler/goflow2/v2/decoders/sflow"
)

// goflow2 v2.2.6 omits flags in structured sampled-IP records and only copies
// the low flag octet for raw TCP headers. Read the sample's complete flag bits
// separately, and distinguish a truncated/missing TCP header from flags=0.
func sflowTCPFlags(sample interface{}) TCPFlagObservation {
	var records []sflow.FlowRecord
	switch s := sample.(type) {
	case sflow.FlowSample:
		records = s.Records
	case sflow.ExpandedFlowSample:
		records = s.Records
	}
	var result TCPFlagObservation
	for _, record := range records {
		switch r := record.Data.(type) {
		case sflow.SampledIPv4:
			result = TCPFlagObservation{r.TcpFlags, r.Protocol == 6}
		case sflow.SampledIPv6:
			result = TCPFlagObservation{r.TcpFlags, r.Protocol == 6}
		case sflow.SampledHeader:
			result = rawTCPFlags(r.Protocol, r.HeaderData)
		}
	}
	return result
}
func rawTCPFlags(protocol uint32, b []byte) TCPFlagObservation {
	var eth uint16
	switch protocol {
	case 1:
		if len(b) < 14 {
			return TCPFlagObservation{}
		}
		eth = binary.BigEndian.Uint16(b[12:14])
		b = b[14:]
		for eth == 0x8100 || eth == 0x88a8 || eth == 0x9100 {
			if len(b) < 4 {
				return TCPFlagObservation{}
			}
			eth = binary.BigEndian.Uint16(b[2:4])
			b = b[4:]
		}
	case 11:
		eth = 0x0800
	case 12:
		eth = 0x86dd
	default:
		return TCPFlagObservation{}
	}
	switch eth {
	case 0x0800:
		if len(b) < 20 || b[0]>>4 != 4 || b[9] != 6 {
			return TCPFlagObservation{}
		}
		n := int(b[0]&15) * 4
		if n < 20 || len(b) < n || binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return TCPFlagObservation{}
		}
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if total < n {
			return TCPFlagObservation{}
		}
		if total < len(b) {
			b = b[:total]
		}
		b = b[n:]
	case 0x86dd:
		if len(b) < 40 || b[0]>>4 != 6 {
			return TCPFlagObservation{}
		}
		total := 40 + int(binary.BigEndian.Uint16(b[4:6]))
		if total > 40 && total < len(b) {
			b = b[:total]
		}
		next := b[6]
		b = b[40:]
		for steps := 0; next != 6; steps++ {
			if steps >= 16 || len(b) < 2 {
				return TCPFlagObservation{}
			}
			n := 0
			switch next {
			case 0, 43, 60:
				n = (int(b[1]) + 1) * 8
			case 44:
				if len(b) < 8 || binary.BigEndian.Uint16(b[2:4])&0xfff8 != 0 {
					return TCPFlagObservation{}
				}
				n = 8
			case 51:
				n = (int(b[1]) + 2) * 4
			default:
				return TCPFlagObservation{}
			}
			if len(b) < n {
				return TCPFlagObservation{}
			}
			next = b[0]
			b = b[n:]
		}
	default:
		return TCPFlagObservation{}
	}
	if len(b) < 20 || b[12]>>4 < 5 {
		return TCPFlagObservation{}
	}
	return TCPFlagObservation{uint32(binary.BigEndian.Uint16(b[12:14]) & 0x0fff), true}
}
