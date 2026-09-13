package main

import (
	"embed"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//go:embed web/*
var webFiles embed.FS

func controlHandler(c *Controller, o *Observer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/tcp-flag-rules", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, tcpFlagRules) })
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, c.Snapshot()) })
	mux.HandleFunc("GET /api/traffic", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, o.Snapshot()) })
	mux.HandleFunc("PUT /api/settings", func(w http.ResponseWriter, r *http.Request) {
		var cfg ControlConfig
		if !readJSON(w, r, &cfg) {
			return
		}
		if e := c.Configure(cfg); e != nil {
			writeError(w, e)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/routes", func(w http.ResponseWriter, r *http.Request) {
		var req RouteRequest
		if !readJSON(w, r, &req) {
			return
		}
		route, e := c.Announce(req)
		if e != nil {
			writeError(w, e)
			return
		}
		writeJSON(w, 201, route)
	})
	mux.HandleFunc("POST /api/routes/{id}/withdraw", func(w http.ResponseWriter, r *http.Request) {
		var req struct{}
		if !readJSON(w, r, &req) {
			return
		}
		if e := c.Withdraw(r.PathValue("id")); e != nil {
			writeError(w, e)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) })
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path
		if name == "/" {
			name = "/index.html"
		}
		if name != "/index.html" && name != "/app.js" && name != "/style.css" {
			http.NotFound(w, r)
			return
		}
		data, e := webFiles.ReadFile("web" + name)
		if e != nil {
			http.NotFound(w, r)
			return
		}
		contentType := "text/html; charset=utf-8"
		if strings.HasSuffix(name, ".js") {
			contentType = "text/javascript; charset=utf-8"
		}
		if strings.HasSuffix(name, ".css") {
			contentType = "text/css; charset=utf-8"
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(data)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		grafanaOrigin := (&url.URL{Scheme: scheme, Host: net.JoinHostPort(host, "3000")}).String()
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-src "+grafanaOrigin+"; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		// No login, as requested. JSON + same-origin checks stop unrelated websites
		// from issuing control commands through an operator's browser.
		if r.Method != "GET" && r.Method != "HEAD" {
			origin := r.Header.Get("Origin")
			if origin != "" {
				u, e := url.Parse(origin)
				if e != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") {
					http.Error(w, "不允許跨來源控制", 403)
					return
				}
			}
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				http.Error(w, "不允許跨來源控制", 403)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if contentType != "application/json" {
		http.Error(w, "請使用 application/json", 415)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		writeError(w, e)
		return false
	}
	if e := d.Decode(new(any)); !errors.Is(e, io.EOF) {
		writeError(w, errors.New("只接受一個 JSON 物件"))
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, e error) {
	writeJSON(w, 400, map[string]string{"error": e.Error()})
}
func uiServer(addr string, c *Controller, o *Observer) *http.Server {
	return &http.Server{Addr: addr, Handler: controlHandler(c, o), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
}
