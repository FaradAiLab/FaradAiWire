package admin

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
)

const (
	wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

// wsClient represents an active RFC 6455 WebSocket client connection.
type wsClient struct {
	conn      net.Conn
	send      chan []byte
	done      chan struct{}
	closeOnce sync.Once
	hub       *WSHub
}

func (c *wsClient) trySend(frame []byte) bool {
	if c == nil || c.send == nil {
		return false
	}
	if c.done == nil {
		select {
		case c.send <- frame:
			return true
		default:
			return false
		}
	}
	select {
	case <-c.done:
		return false
	case c.send <- frame:
		return true
	default:
		return false
	}
}

func (c *wsClient) close() {
	c.closeOnce.Do(func() {
		if c.done != nil {
			close(c.done)
		}
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
}

// WSHub manages active WebSocket client connections and event broadcasting.
type WSHub struct {
	clients        map[*wsClient]bool
	allowedOrigins []string
	mu             sync.RWMutex
	onConnect      func(client *wsClient)
	onMessage      func(client *wsClient, payload []byte)
}

// NewWSHub constructs a new WSHub.
func NewWSHub() *WSHub {
	return &WSHub{
		clients: make(map[*wsClient]bool),
	}
}

// SetOnConnect binds a hook called whenever a client completes handshake.
func (h *WSHub) SetOnConnect(fn func(client *wsClient)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onConnect = fn
}

// SetAllowedOrigins configures the permitted Origin headers for WebSocket requests.
func (h *WSHub) SetAllowedOrigins(origins []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.allowedOrigins = origins
}

// isOriginAllowed validates the Origin header against the request host and configured allowlists.
func (h *WSHub) isOriginAllowed(origin string, reqHost string) bool {
	if origin == "" {
		return true
	}

	h.mu.RLock()
	allowed := h.allowedOrigins
	h.mu.RUnlock()

	if isExplicitlyAllowedOrigin(origin, allowed) {
		return true
	}

	// Only accept browser same-host origins automatically when both Origin and Host resolve to loopback.
	return isLoopbackSameHostOrigin(origin, reqHost)
}

// SetOnMessage binds a hook called whenever a client sends a text message.
func (h *WSHub) SetOnMessage(fn func(client *wsClient, payload []byte)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onMessage = fn
}

// ClientCount returns the count of active connected clients.
func (h *WSHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Broadcast serializes and dispatches an event to all connected clients.
func (h *WSHub) Broadcast(event interface{}) {
	data, err := json.Marshal(event)
	if err != nil {
		slog.Error("Failed to marshal WebSocket broadcast event", slog.String("error", err.Error()))
		return
	}

	frame := encodeTextFrame(data)

	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		if !client.trySend(frame) {
			// Client closed or send channel full: drop frame to prevent slow client blocking
			slog.Warn("WebSocket client buffer full, dropping frame")
		}
	}
}

// SendDirect sends a message directly to a single client connection safely.
func (h *WSHub) SendDirect(client *wsClient, event interface{}) {
	if client == nil {
		return
	}
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	frame := encodeTextFrame(data)

	h.mu.RLock()
	defer h.mu.RUnlock()

	if !h.clients[client] {
		return
	}

	client.trySend(frame)
}

func (h *WSHub) register(c *wsClient) {
	h.mu.Lock()
	h.clients[c] = true
	connectFn := h.onConnect
	h.mu.Unlock()

	if connectFn != nil {
		connectFn(c)
	}
}

func (h *WSHub) unregister(c *wsClient) {
	if c == nil {
		return
	}
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
	c.close()
}

// encodeTextFrame creates an RFC 6455 unmasked text frame (server-to-client).
func encodeTextFrame(payload []byte) []byte {
	length := len(payload)
	var frame []byte

	if length <= 125 {
		frame = make([]byte, 2+length)
		frame[0] = 0x81 // FIN + opcode 1 (text)
		frame[1] = byte(length)
		copy(frame[2:], payload)
	} else if length <= 65535 {
		frame = make([]byte, 4+length)
		frame[0] = 0x81
		frame[1] = 126
		binary.BigEndian.PutUint16(frame[2:4], uint16(length))
		copy(frame[4:], payload)
	} else {
		frame = make([]byte, 10+length)
		frame[0] = 0x81
		frame[1] = 127
		binary.BigEndian.PutUint64(frame[2:10], uint64(length))
		copy(frame[10:], payload)
	}
	return frame
}

// encodePongFrame creates an RFC 6455 pong frame.
func encodePongFrame(payload []byte) []byte {
	frame := make([]byte, 2+len(payload))
	frame[0] = 0x8A // FIN + opcode 10 (pong)
	frame[1] = byte(len(payload))
	copy(frame[2:], payload)
	return frame
}

// ServeHTTP handles the WebSocket handshake and spawns client reader/writer loops.
func (h *WSHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// SEC-CSWSH: Prevent Cross-Site WebSocket Hijacking
	origin := r.Header.Get("Origin")
	if origin != "" && !h.isOriginAllowed(origin, r.Host) {
		http.Error(w, "Forbidden: unauthorized WebSocket origin", http.StatusForbidden)
		return
	}

	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "Expected websocket upgrade", http.StatusBadRequest)
		return
	}

	connHeader := strings.ToLower(r.Header.Get("Connection"))
	if !strings.Contains(connHeader, "upgrade") {
		http.Error(w, "Expected upgrade connection header", http.StatusBadRequest)
		return
	}

	secKey := r.Header.Get("Sec-WebSocket-Key")
	if secKey == "" {
		http.Error(w, "Missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	// Compute Sec-WebSocket-Accept
	hKey := sha1.New()
	hKey.Write([]byte(secKey + wsGUID))
	acceptKey := base64.StdEncoding.EncodeToString(hKey.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Webserver does not support hijacking", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Send RFC 6455 switching protocols handshake
	handshake := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n"
	if _, err := bufrw.WriteString(handshake); err != nil {
		_ = conn.Close()
		return
	}
	if err := bufrw.Flush(); err != nil {
		_ = conn.Close()
		return
	}

	client := &wsClient{
		conn: conn,
		send: make(chan []byte, 64),
		done: make(chan struct{}),
		hub:  h,
	}

	h.register(client)

	// Writer loop
	go func() {
		defer h.unregister(client)
		for {
			select {
			case <-client.done:
				return
			case msg := <-client.send:
				if _, err := conn.Write(msg); err != nil {
					return
				}
			}
		}
	}()

	// Reader loop
	reader := bufrw.Reader
	for {
		payload, opcode, err := readFrame(reader)
		if err != nil {
			break
		}
		if opcode == 0x8 { // Close frame
			break
		}
		if opcode == 0x9 { // Ping frame -> respond with Pong
			client.trySend(encodePongFrame(payload))
			continue
		}
		if opcode == 0x1 && len(payload) > 0 { // Text frame
			h.mu.RLock()
			msgFn := h.onMessage
			h.mu.RUnlock()
			if msgFn != nil {
				msgFn(client, payload)
			}
		}
	}
	h.unregister(client)
}

// readFrame reads and decodes a single masked RFC 6455 frame from client.
func readFrame(r *bufio.Reader) ([]byte, byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, 0, err
	}

	opcode := header[0] & 0x0F
	masked := (header[1] & 0x80) != 0
	length := int(header[1] & 0x7F)

	if length == 126 {
		lenBytes := make([]byte, 2)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return nil, opcode, err
		}
		length = int(binary.BigEndian.Uint16(lenBytes))
	} else if length == 127 {
		lenBytes := make([]byte, 8)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return nil, opcode, err
		}
		length = int(binary.BigEndian.Uint64(lenBytes))
	}

	if length > 10*1024*1024 { // 10MB sanity cap
		return nil, opcode, errors.New("frame payload too large")
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(r, maskKey); err != nil {
			return nil, opcode, err
		}
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, opcode, err
	}

	if masked {
		for i := 0; i < length; i++ {
			payload[i] ^= maskKey[i%4]
		}
	}

	return payload, opcode, nil
}
