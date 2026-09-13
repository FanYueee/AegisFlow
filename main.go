// Command aegisflow collects sFlow and NetFlow v9/IPFIX directly via the
// goflow2 decoder/producer libraries (not the goflow2 CLI pipeline) and
// exposes the extracted flow metadata as Prometheus metrics.
package main

import (
	"bytes"
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/netsampler/goflow2/v2/decoders/sflow"
	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	sflowAddr   = flag.String("sflow-listen", ":6343", "UDP address to listen for sFlow on")
	netflowAddr = flag.String("netflow-listen", ":2055", "UDP address to listen for NetFlow v9/IPFIX on")
	uiAddr      = flag.String("ui-listen", ":8080", "Internal observation/control UI address (no authentication)")
	controlFile = flag.String("control-state", "data/control.json", "Persistent BGP control state")
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

var liveObserver = newObserver()

func main() {
	flag.Parse()
	control, err := newController(*controlFile)
	if err != nil {
		log.Fatalf("control state: %v", err)
	}
	if err := control.RequireLive(); err != nil {
		log.Fatalf("control mode: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rules, err := newRuleEngine(filepath.Join(filepath.Dir(*controlFile), "rules.json"), control)
	if err != nil {
		log.Fatalf("rule state: %v", err)
	}
	liveRules.Store(rules)
	go rules.Run(ctx)
	go liveObserver.Run(ctx)
	go control.Run(ctx)
	ui := uiServer(*uiAddr, control, liveObserver)
	go func() {
		log.Printf("control UI on %s", *uiAddr)
		if err := ui.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("control UI: %v", err)
		}
	}()
	go serveMetrics(*metricsAddr)
	go runSFlowCollector(*sflowAddr)
	go runNetFlowCollector(*netflowAddr)
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = ui.Shutdown(shutdown)
	// Routes remain in the external GoBGP daemon; persisted expiry/reconciliation
	// resumes on restart. Shutting down the collector does not withdraw other RIBs.
}

func serveMetrics(addr string) {
	http.Handle("/metrics", promhttp.Handler())
	realtime := prometheus.NewRegistry()
	realtime.MustRegister(newRealtimeCollector(liveObserver))
	http.Handle("/metrics/realtime", promhttp.HandlerFor(realtime, promhttp.HandlerOpts{}))
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
		samples := protoproducer.GetSFlowFlowSamples(&packet)
		for i, msg := range flowMessages {
			RecordFlow(msg, "sflow", raddr.IP, 1, sflowTCPFlags(samples[i]))
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
