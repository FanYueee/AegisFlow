package main

import "net/http"

func registerRuleHandlers(mux *http.ServeMux) {
	withEngine := func(fn func(*RuleEngine, http.ResponseWriter, *http.Request)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			e := liveRules.Load()
			if e == nil {
				writeJSON(w, 503, map[string]string{"error": "規則引擎尚未啟動"})
				return
			}
			fn(e, w, r)
		}
	}
	mux.HandleFunc("GET /api/rules", withEngine(func(e *RuleEngine, w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, e.Snapshot()) }))
	save := withEngine(func(e *RuleEngine, w http.ResponseWriter, r *http.Request) {
		var rule Rule
		if !readJSON(w, r, &rule) {
			return
		}
		saved, err := e.Upsert(r.PathValue("id"), rule)
		if err != nil {
			writeError(w, ruleError(err))
			return
		}
		writeJSON(w, 200, saved)
	})
	mux.HandleFunc("POST /api/rules", save)
	mux.HandleFunc("PUT /api/rules/{id}", save)
	mux.HandleFunc("POST /api/rules/{id}/enabled", withEngine(func(e *RuleEngine, w http.ResponseWriter, r *http.Request) {
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if err := e.Enable(r.PathValue("id"), req.Enabled); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("DELETE /api/rules/{id}", withEngine(func(e *RuleEngine, w http.ResponseWriter, r *http.Request) {
		var req struct{}
		if !readJSON(w, r, &req) {
			return
		}
		if err := e.Delete(r.PathValue("id")); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/rules/{id}/preview", withEngine(func(e *RuleEngine, w http.ResponseWriter, r *http.Request) {
		var req struct {
			Value float64 `json:"value"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		v, err := e.Preview(r.PathValue("id"), req.Value)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, 200, v)
	}))
}
