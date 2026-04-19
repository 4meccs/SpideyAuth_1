// api/status.go – GET /status
// Returns the service status and API version mapping.
// The client reads versions["3.4"] to get the URL prefix for all auth endpoints.
package handler

import (
	"encoding/json"
	"net/http"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"message": false, // client does: if true then warn(msg) crashClient() end
		"versions": map[string]string{
			"3.4": "v1",
		},
	})
}
