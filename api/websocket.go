// api/websocket.go
// WebSocket endpoint: /wshttpemu
//
// The client connects via WebSocket and uses this as an HTTP proxy for
// auth requests. Message format:
//
//   Client → Server: { "Opcode": "PING", "Data": {} }
//   Server → Client: { "Opcode": "PONG" }
//
//   Client → Server: { "Opcode": "REQUEST", "Data": { "Url": "https://..." }, "Id": 12345 }
//   Server → Client: { "Opcode": "RESPONSE", "Data": "<response body>", "Id": 12345 }
//
// The server performs a GET to the requested URL and returns the response body
// wrapped with the message ID so the client can match request to response.
// The response body is prefixed with |__ID__| to allow routing.
//
// NOTE: Vercel serverless functions don't support persistent WebSocket connections
// natively. For production use, deploy the WebSocket handler on a long-running
// process (e.g. Railway, Fly.io, or a dedicated Vercel Edge Function). This file
// provides the correct protocol implementation.
package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type wsMessage struct {
	Opcode string          `json:"Opcode"`
	Data   json.RawMessage `json:"Data"`
	Id     int             `json:"Id,omitempty"`
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

func Handler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
		return
	}
	defer conn.Close()

	for {
		var msg wsMessage
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}

		switch msg.Opcode {
		case "PING":
			_ = conn.WriteJSON(wsMessage{Opcode: "PONG", Data: json.RawMessage(`{}`)})

		case "REQUEST":
			var reqData struct {
				Url string `json:"Url"`
			}
			if err := json.Unmarshal(msg.Data, &reqData); err != nil || reqData.Url == "" {
				continue
			}

			go func(id int, targetURL string) {
				body := fetchURL(targetURL)
				// Embed the request ID in the response so the client can correlate it.
				// The client looks for the pattern |__ID__| in the message.
				response := fmt.Sprintf("|__%d__|%s", id, body)
				_ = conn.WriteJSON(wsMessage{
					Opcode: "RESPONSE",
					Data:   json.RawMessage(`"` + jsonEscape(response) + `"`),
					Id:     id,
				})
			}(msg.Id, reqData.Url)
		}
	}
}

func fetchURL(targetURL string) string {
	resp, err := httpClient.Get(targetURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return ""
	}
	return string(body)
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	// json.Marshal adds surrounding quotes – strip them
	return string(b[1 : len(b)-1])
}