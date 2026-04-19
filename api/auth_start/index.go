// api/auth_start.go
// GET /{version}/auth/start/{session_token}?t=...
//
// Second step of the SpideyAuth v3.4 handshake.
// The client sends a payload encrypted with the 8-byte extended key.
// The server responds with 9 fields including the protected script source.
//
// Routed via vercel.json: /:version/auth/start/:token → /api/auth_start?token=$token
package handler

import (
	"fmt"
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
	urlToken := r.URL.Query().Get("token") // session URL token from init response[11]
	t := r.URL.Query().Get("t")

	if urlToken == "" || t == "" {
		w.Write([]byte("!Missing parameters"))
		return
	}

	// ── 2. Load session ───────────────────────────────────────────────────────
	sess, err := db.GetSessionByURLToken(urlToken)
	if err != nil || sess == nil {
		w.Write([]byte("!Session not found"))
		return
	}

	// ── 3. Build the 8-byte extended cipher key ───────────────────────────────
	// Layout: [ct1, ek1, ct2, ek3, ct3, ek5, ct4, ek7]
	extKey := crypto.EightByteKey(
		sess.CT1, sess.CT2, sess.CT3, sess.CT4,
		sess.ExtKey1, sess.ExtKey3, sess.ExtKey5, sess.ExtKey7,
	)
	startCipher := crypto.NewCipher(extKey)

	// ── 4. Decode the start request payload ──────────────────────────────────
	// After decoding we get 6 fields:
	//   [0]  checksum
	//   [1]  hash block (numericHash(initResp[13]+2848) ..
	//                    numericHash(combinedSeed+antiTamperCode) ..
	//                    numericHash(sessionToken+nonce1))
	//        – the server cannot fully verify this (antiTamperCode unknown)
	//   [2]  serverNonces[5]  (client's sn[5])
	//   [3]  combinedSeed
	//   [4]  serverNonces[6]  (client's sn[6])
	//   [5]  serverNonces[4]  (client's sn[4])
	fields := startCipher.DecodeMessage(t)
	fmt.Printf("=== START REQUEST ===\n")
	fmt.Printf("Session URL Token: %s\n", urlToken)
	fmt.Printf("extKey1: %d, extKey3: %d, extKey5: %d, extKey7: %d\n", sess.ExtKey1, sess.ExtKey3, sess.ExtKey5, sess.ExtKey7)
	fmt.Printf("CT1: %d, CT2: %d, CT3: %d, CT4: %d\n", sess.CT1, sess.CT2, sess.CT3, sess.CT4)
	extKey := crypto.EightByteKey(sess.CT1, sess.CT2, sess.CT3, sess.CT4, sess.ExtKey1, sess.ExtKey3, sess.ExtKey5, sess.ExtKey7)
	fmt.Printf("Extended Key: %v\n", extKey)
	fmt.Printf("Start Request Fields Count: %d\n", len(fields))
	for i, f := range fields {
    	fmt.Printf("Field[%d]: %s\n", i, f)
	}
	
	if len(fields) < 6 {
		w.Write([]byte("!Malformed start payload"))
		return
	}

	parseInt := func(s string) int64 {
		v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return v
	}

	sn5 := parseInt(fields[2])       // client's serverNonces[5]
	combinedSeed := parseInt(fields[3])
	sn6 := parseInt(fields[4])       // client's serverNonces[6]
	sn4 := parseInt(fields[5])       // client's serverNonces[4]

	// ── 5. Store combinedSeed (used by heartbeat handler) ────────────────────
	_ = db.UpdateSessionCombinedSeed(sess.ID, combinedSeed)

	// ── 6. Fetch script for protected payload ─────────────────────────────────
	script, err := db.GetScript(sess.ScriptID)
	if err != nil || script == nil {
		w.Write([]byte("!Script not available"))
		return
	}

	// ── 7. Build server proof ─────────────────────────────────────────────────
	// Uses stringChecksum("?") = 63 as JobId fallback.
	// The client's first attempt uses the real JobId; its second attempt uses "?".
	// We always produce the "?" proof so the client succeeds on attempt 2.
	serverProof := crypto.BuildStartServerProof(sn4, sn5, sn6, sess.ServerNonce2Init)

	// ── 8. Build 9-field start response ──────────────────────────────────────
	// Field layout (0-indexed):
	//
	//  [0]  transformA + sn4   → client: startResponse[1] - sn4 = transformA
	//  [1]  scriptNote
	//  [2]  serverProof        → client verifies server identity (3 hashes)
	//  [3]  scriptName
	//  [4]  transformC + sn6   → client: startResponse[5] - sn6 = transformC
	//  [5]  protectedScript    (the actual Lua source to execute)
	//  [6]  transformB + sn5   → client: startResponse[7] - sn5 = transformB
	//  [7]  userIdentifier
	//  [8]  userNote
	const (
		transformA = int64(97)
		transformB = int64(53)
		transformC = int64(7)
	)

	userID := script.UserIdentifier
	if userID == "" {
		userID = "?"
	}
	userNote := script.UserNote
	if userNote == "" {
		userNote = "?"
	}

	response := []string{
		strconv.FormatInt(transformA+sn4, 10),  // [0]
		script.ScriptNote,                       // [1]
		serverProof,                             // [2]
		script.Name,                             // [3]
		strconv.FormatInt(transformC+sn6, 10),  // [4]
		script.ProtectedPayload,                 // [5]
		strconv.FormatInt(transformB+sn5, 10),  // [6]
		userID,                                  // [7]
		userNote,                                // [8]
	}

	// ── 9. Encode with the 8-byte extended key ────────────────────────────────
	startCipher.ResetEnc()
	encoded := startCipher.EncodeStrings(response)

	w.Write([]byte(encoded))
}
