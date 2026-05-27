//go:build linux

package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

//go:embed static
var staticFS embed.FS

// Dashboard owns the HTTP server, the WebSocket upgrader, and the set
// of connected clients. Events broadcast from the main event loop fan
// out to every connected client.
type Dashboard struct {
	upgrader websocket.Upgrader
	mu       sync.Mutex
	clients  map[*websocket.Conn]struct{}
}

func NewDashboard() *Dashboard {
	return &Dashboard{
		upgrader: websocket.Upgrader{
			// Dev-only: allow any origin. In production this should be
			// constrained to known hosts.
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		clients: make(map[*websocket.Conn]struct{}),
	}
}

// Serve starts the HTTP server. Blocks until the server exits.
func (d *Dashboard) Serve(addr string) error {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/events", d.handleWS)

	log.Printf("dashboard: listening on http://%s", addr)
	return http.ListenAndServe(addr, mux)
}

// handleWS upgrades the request and registers the new client.
func (d *Dashboard) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := d.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("dashboard: upgrade error: %v", err)
		return
	}
	d.register(conn)

	// Reader goroutine: drains incoming frames (we don't expect any),
	// detects disconnects, and cleans up.
	go func() {
		defer d.unregister(conn)
		conn.SetReadLimit(512)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
}

func (d *Dashboard) register(conn *websocket.Conn) {
	d.mu.Lock()
	d.clients[conn] = struct{}{}
	n := len(d.clients)
	d.mu.Unlock()
	log.Printf("dashboard: client connected from %s (%d total)", conn.RemoteAddr(), n)
}

func (d *Dashboard) unregister(conn *websocket.Conn) {
	d.mu.Lock()
	_, was := d.clients[conn]
	delete(d.clients, conn)
	n := len(d.clients)
	d.mu.Unlock()
	_ = conn.Close()
	if was {
		log.Printf("dashboard: client disconnected (%d remaining)", n)
	}
}

// Broadcast sends the event as JSON to every connected client. Failed
// writes drop the client. Non-blocking: a dead client doesn't stall
// the event loop.
func (d *Dashboard) Broadcast(evt *Event) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for conn := range d.clients {
		if err := conn.WriteJSON(evt); err != nil {
			_ = conn.Close()
			delete(d.clients, conn)
		}
	}
}
