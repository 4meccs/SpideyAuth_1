// api/heartbeat.go
// GET /{version}/auth/heartbeat?t=...&s=...
//
// Keep-alive sent every 20 seconds. The client verifies the response value
// exactly. A wrong response immediately poisons the heartbeat and crashes the client.
//
// NOTE: The heartbeat payload does NOT have a checksum prepend (unlike init/start).
//       It is simply 3 cipher-encoded strings.
//
// Routed via vercel.json: /:version/auth/heartbeat → /api/heartbeat
package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/4meccs/SpideyAuth_1/pkg/crypto"
	"github.com/4meccs/SpideyAuth_1/pkg/db"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// ── 1. Parse parameters ──────────────────────────────────────────────────
	sessionID := r.URL.Query().Get("s") // from initResponse[12] / session URL token
	t := r.URL.Query().Get("t")

	if sessionID == "" || t == "" {
		w.Write([]byte("FAIL"))
		return
	}

	// ── 2. Load session ───────────────────────────────────────────────────────
	sess, err := db.GetSessionByURLToken(sessionID)
	if err != nil || sess == nil {
		w.Write([]byte("NOT_FOUND"))
		return
	}

	// ── 3. Build extended cipher key and decode the payload ──────────────────
	// Heartbeat payload (3 fields, NO checksum prepend):
	//   [0]  hbNonce2
	//   [1]  hash block  (numericHash(hbNonce2+sessionToken) .. numericHash(hbNonce1+nonce2))
	//   [2]  hbNonce1
	extKey := crypto.EightByteKey(
		sess.CT1, sess.CT2, sess.CT3, sess.CT4,
		sess.ExtKey1, sess.ExtKey3, sess.ExtKey5, sess.ExtKey7,
	)
	hbCipher := crypto.NewCipher(extKey)
	fields := hbCipher.DecodeMessage(t)

	if len(fields) < 3 {
		w.Write([]byte("FAIL"))
		return
	}

	parseInt := func(s string) int64 {
		v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return v
	}

	hbNonce2 := parseInt(fields[0])
	hbNonce1 := parseInt(fields[2])

	// ── 4. Compute the expected response value ────────────────────────────────
	// The client verifies:
	//   expectedGood     = numericHash(hbNonce1 * hbNonce2 % 100000 + combinedSeed + 8410)
	//   expectedShutdown = numericHash(hbNonce1 * hbNonce2 % 100000 + combinedSeed + 8410 + 4919)
	var responseValue string
	if sess.ShouldTerminate {
		responseValue = crypto.BuildHeartbeatShutdownResponse(hbNonce1, hbNonce2, sess.CombinedSeed)
	} else {
		responseValue = crypto.BuildHeartbeatGoodResponse(hbNonce1, hbNonce2, sess.CombinedSeed)
	}

	// ── 5. Encode and return ──────────────────────────────────────────────────
	hbCipher.ResetEnc()
	encoded := hbCipher.EncodeString(responseValue)

	// Update heartbeat timestamp (async – don't block the response)
	go func() { _ = db.TouchHeartbeat(sess.ID) }()

	w.Write([]byte(encoded))
}
