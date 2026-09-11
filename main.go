// Command aegisflow collects sFlow and NetFlow v9/IPFIX directly via the
// goflow2 decoder/producer libraries (not the goflow2 CLI pipeline) and
// exposes the extracted flow metadata as Prometheus metrics.
package main

import (
	"bytes"
	"flag"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/netsampler/goflow2/v2/decoders/sflow"
	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	sflowAddr   = flag.String("sflow-listen", ":6343", "UDP address to listen for sFlow on")
	netflowAddr = flag.String("netflow-listen", ":2055", "UDP address to listen for NetFlow v9/IPFIX on")
	metricsAddr = flag.String("metrics-listen", ":2112", "HTTP address to expose Prometheus metrics on")

	// netflowSamplingRate is applied to NetFlow/IPFIX flows that don't report
	// their own sampling rate over the protocol. Some exporters (e.g. MikroTik
	// RouterOS packet-sampling) sample without ever announcing the ratio, so
	// it has to be supplied manually to avoid undercounting traffic.
	netflowSamplingRate = flag.Uint64("netflow-sampling-rate", 2, "fallback sampling rate for NetFlow/IPFIX flows that don't announce their own (e.g. MikroTik packet-sampling)")
)

// templateStore holds one NetFlow/IPFIX template system per exporter, since
// templates are only valid within the exporter that sent them.
type templateStore struct {
	mu   sync.RWMutex
	byIP map[string]netflow.NetFlowTemplateSystem
}

func newTemplateStore() *templateStore {
	return &templateStore{byIP: make(map[string]netflow.NetFlowTemplateSystem)}
}

func (s *templateStore) get(key string) netflow.NetFlowTemplateSystem {
	s.mu.RLock()
	ts, ok := s.byIP[key]
	s.mu.RUnlock()
	if ok {
		return ts
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if ts, ok = s.byIP[key]; ok {
		return ts
	}
	ts = netflow.CreateTemplateSystem()
	s.byIP[key] = ts
	return ts
}

func main() {
	flag.Parse()

	go serveMetrics(*metricsAddr)
	go runSFlowCollector(*sflowAddr)
	runNetFlowCollector(*netflowAddr)
}

func serveMetrics(addr string) {
	http.Handle("/metrics", promhttp.Handler())
	log.Printf("serving Prometheus metrics on %s/metrics", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("metrics server: %v", err)
	}
}

// runSFlowCollector listens for sFlow v5 datagrams and decodes each one
// directly via the goflow2 decoder/producer API.
func runSFlowCollector(addr string) {
	conn := mustListenUDP("sflow", addr)
	defer conn.Close()

	buf := make([]byte, 65535)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("sflow: read error: %v", err)
			continue
		}

		var packet sflow.Packet
		if err := sflow.DecodeMessageVersion(bytes.NewBuffer(buf[:n]), &packet); err != nil {
			log.Printf("sflow: decode error: %v", err)
			continue
		}

		flowMessages, err := protoproducer.ProcessMessageSFlowConfig(&packet, nil)
		if err != nil {
			log.Printf("sflow: producer error: %v", err)
			continue
		}
		for _, msg := range flowMessages {
			RecordFlow(msg, "sflow", raddr.IP, 1)
		}
	}
}

// runNetFlowCollector listens for NetFlow v9 / IPFIX datagrams. Templates
// are tracked per exporter address, and sampling rate is tracked globally
// (the sampling rate system is keyed internally by version+obsDomainId).
func runNetFlowCollector(addr string) {
	conn := mustListenUDP("netflow", addr)
	defer conn.Close()

	templates := newTemplateStore()
	samplingRates := protoproducer.CreateSamplingSystem()

	buf := make([]byte, 65535)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("netflow: read error: %v", err)
			continue
		}

		ts := templates.get(raddr.IP.String())

		var packetNFv9 netflow.NFv9Packet
		var packetIPFIX netflow.IPFIXPacket
		if err := netflow.DecodeMessageVersion(bytes.NewBuffer(buf[:n]), ts, &packetNFv9, &packetIPFIX); err != nil {
			log.Printf("netflow: decode error: %v", err)
			continue
		}

		switch {
		case packetNFv9.Version == 9:
			msgs, err := protoproducer.ProcessMessageNetFlowV9Config(&packetNFv9, samplingRates, nil)
			if err != nil {
				log.Printf("netflow: producer error (v9): %v", err)
				continue
			}
			for _, msg := range msgs {
				RecordFlow(msg, "netflow9", raddr.IP, *netflowSamplingRate)
			}
		case packetIPFIX.Version == 10:
			msgs, err := protoproducer.ProcessMessageIPFIXConfig(&packetIPFIX, samplingRates, nil)
			if err != nil {
				log.Printf("netflow: producer error (ipfix): %v", err)
				continue
			}
			for _, msg := range msgs {
				RecordFlow(msg, "ipfix", raddr.IP, *netflowSamplingRate)
			}
		}
	}
}

func mustListenUDP(name, addr string) *net.UDPConn {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("%s: resolve %s: %v", name, addr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("%s: listen %s: %v", name, addr, err)
	}
	log.Printf("%s: listening on %s", name, addr)
	return conn
}
