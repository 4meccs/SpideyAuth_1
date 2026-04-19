// api/auth_init.go
// GET /{version}/auth/{script_id}/init?t=...&v=...&k=...
//
// This is the first authenticated request in the SpideyAuth v3.4 flow.
// It decodes the client payload, validates the license key and HWID,
// then returns a 16-field encrypted response that drives the rest of the session.
//
// Routed via vercel.json: /:version/auth/:script_id/init → /api/auth_init?script_id=$script_id
package handler

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/4meccs/SpideyAuth_1/pkg/crypto"
	"github.com/4meccs/SpideyAuth_1/pkg/db"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// ── 1. Parse query parameters ────────────────────────────────────────────
	scriptID := r.URL.Query().Get("script_id")
	licenseKey := r.URL.Query().Get("k")
	t := r.URL.Query().Get("t")
	_ = r.URL.Query().Get("v") // script version (stored for future validation)

	if scriptID == "" || t == "" {
		http.Error(w, "!Missing required parameters", http.StatusBadRequest)
		return
	}

	// ── 2. Decode the init request payload (initial key = {0}) ───────────────
	// The client encodes with key={[0]=0}, so the only cipher operation is +4096%256
	// which with key[0]=0 is a no-op. The payload is effectively plain nibble-encoded.
	//
	// After decoding we get 13 fields:
	//   [0]  = checksum (numericHash(sum_of_subsequent_bytes + 12268))
	//   [1]  = nonce2
	//   [2]  = hash block (3 concatenated hashes, used for anti-tamper, not verified here)
	//   [3]  = combinedKey
	//   [4]  = nonce1
	//   [5]  = clientTokens[3] + 19053  → clientToken3 = fields[5] - 19053
	//   [6]  = serverNonces[1]           (client-generated, echoed back by server)
	//   [7]  = clientTokens[4] + 15411  → clientToken4 = fields[7] - 15411
	//   [8]  = serverNonces[3]
	//   [9]  = clientTokens[2] + 181    → clientToken2 = fields[9] - 181
	//   [10] = serverNonces[2]
	//   [11] = clientTokens[1] + 8410   → clientToken1 = fields[11] - 8410
	//   [12] = hwid
	initCipher := crypto.NewCipher(crypto.InitialKey)
	fields := initCipher.DecodeMessage(t)

	if len(fields) < 13 {
		w.Write([]byte("!Malformed request"))
		return
	}

	// Extract numeric fields (tolerate malformed strings gracefully)
	parseInt := func(s string) int64 {
		v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return v
	}

	nonce2 := parseInt(fields[1])
	nonce1 := parseInt(fields[4])
	clientToken3 := parseInt(fields[5]) - 19053
	sn1 := parseInt(fields[6]) // client's serverNonces[1]
	clientToken4 := parseInt(fields[7]) - 15411
	sn3 := parseInt(fields[8]) // client's serverNonces[3]
	clientToken2 := parseInt(fields[9]) - 181
	sn2 := parseInt(fields[10]) // client's serverNonces[2]
	clientToken1 := parseInt(fields[11]) - 8410
	hwid := fields[12]

	// ── 3. Validate the license key ──────────────────────────────────────────
	entry, err := db.GetWhitelistEntry(scriptID, licenseKey)
	if err != nil {
		w.Write([]byte("!Server error, please try again"))
		return
	}
	if entry == nil {
		w.Write([]byte("!Invalid key"))
		return
	}
	if entry.IsBanned {
		reason := entry.BanReason
		if reason == "" {
			reason = "You are banned"
		}
		w.Write([]byte("!" + reason + ";;lrm_is_diff_msg"))
		return
	}

	// Expiry check
	if entry.ExpiresAt != nil && entry.ExpiresAt.Before(time.Now()) {
		w.Write([]byte("!Your license has expired"))
		return
	}

	// Max-uses check
	if entry.MaxUses > 0 && entry.TotalUses >= entry.MaxUses {
		w.Write([]byte("!License use limit reached"))
		return
	}

	// HWID check / binding
	if entry.HWID == nil || *entry.HWID == "" {
		if hwid != "" && hwid != "?" {
			if err := db.LinkHWID(entry.ID, hwid); err != nil {
				// non-fatal: continue
				_ = err
			}
		}
	} else if hwid != "?" && *entry.HWID != hwid {
		w.Write([]byte("!HWID mismatch. Reset your HWID or contact the developer"))
		return
	}

	// Fetch script metadata
	script, err := db.GetScript(scriptID)
	if err != nil || script == nil {
		w.Write([]byte("!Script not found"))
		return
	}

	// ── 4. Generate session values ───────────────────────────────────────────
	sessionToken := randInt64(1000000, 9999999999)
	sessionURLToken := randURLToken()

	// Server-generated extKey bytes (0–255) that become the extended cipher key
	extKey1 := randInt64(0, 255)
	extKey3 := randInt64(0, 255)
	extKey5 := randInt64(0, 255)
	extKey7 := randInt64(0, 255)

	// Arbitrary runtime protection values (auth transform constants)
	// The protected script may use these in verification closures.
	// Any reasonable non-zero values work.
	const (
		transformA = int64(97)  // prime
		transformB = int64(53)  // prime
		transformC = int64(7)   // small prime
	)

	// Values the client will compute as:
	//   authPayload    = response[7] - sn1
	//   authModifier   = response[2] - sn2
	//   authTransformer= response[4] - sn3
	r7val := transformA + sn1
	r2val := transformB + sn2
	r4val := transformC + sn3

	// Start hash input (the client includes this in the start payload hash)
	startHashInput := randInt64(100000, 9999999)

	// Determine lifetime flag and max-uses limit
	isLifetime := entry.ExpiresAt == nil
	maxUses := entry.MaxUses       // 0 = unlimited
	totalUses := entry.TotalUses
	discordID := entry.DiscordID
	if discordID == "" {
		discordID = "Not specified"
	}

	// The value the client reads as maxUsesLimit:
	// if initResponse[14] (0-indexed) == "-1" → unlimited
	maxUsesLimitStr := "-1"
	if maxUses > 0 {
		maxUsesLimitStr = strconv.FormatInt(maxUses, 10)
	}

	// Expiry as Unix timestamp (0 = never)
	expiryTS := int64(0)
	if entry.ExpiresAt != nil {
		expiryTS = entry.ExpiresAt.Unix()
	}

	// ── 5. Build the server proof for the init response ──────────────────────
	serverProof := crypto.BuildInitServerProof(sn1, sn2, sn3, isLifetime)

	// ── 6. Build the 16-field init response ──────────────────────────────────
	// Field layout (0-indexed, these are what the client reads as 1-indexed Lua arrays):
	//
	//  [0]  maxUses + nonce2                  → client: initResponse[1] - nonce2 = maxUses
	//  [1]  extKey5 string                    → extended cipher key [5] (Lua reads as initResponse[2])
	//  [2]  transformB + sn2                  → client: initResponse[3] - sn2 = authModifier
	//  [3]  expiryTimestamp + nonce1          → client: initResponse[4] - nonce1 = expiryTimestamp
	//  [4]  transformC + sn3                  → client: initResponse[5] - sn3 = authTransformer
	//  [5]  extKey7 string                    → extended cipher key [7] (Lua reads as initResponse[6])
	//  [6]  extKey3 string                    → extended cipher key [3] (Lua reads as initResponse[7])
	//  [7]  transformA + sn1                  → client: initResponse[8] - sn1 = authPayload
	//  [8]  extKey1 string                    → extended cipher key [1] (Lua reads as initResponse[9])
	//  [9]  sessionToken                      → used in heartbeat hash
	//  [10] serverProof                       → client verifies server identity
	//  [11] sessionURLToken                   → used in /auth/start/{token} and ?s= heartbeat
	//  [12] startHashInput                    → included in start payload hash
	//  [13] maxUsesLimitStr ("-1"=unlimited)  → client checks for unlimited
	//  [14] totalUses string
	//  [15] discordID
	response := []string{
		strconv.FormatInt(maxUses+nonce2, 10),   // [0]
		string([]byte{byte(extKey5)}), // strconv.FormatInt(extKey5, 10),          // [1] ← extKey5 (Lua initResponse[2])
		strconv.FormatInt(r2val, 10),            // [2]
		strconv.FormatInt(expiryTS+nonce1, 10),  // [3]
		strconv.FormatInt(r4val, 10),            // [4]
		string([]byte{byte(extKey7)}), // strconv.FormatInt(extKey7, 10),          // [5] ← extKey7 (Lua initResponse[6])
		string([]byte{byte(extKey3)}), // strconv.FormatInt(extKey3, 10),          // [6] ← extKey3 (Lua initResponse[7])
		string([]byte{byte(extKey1)}), // strconv.FormatInt(r7val, 10),            // [7]
		string(rune(extKey1)) // strconv.FormatInt(extKey1, 10),          // [8] ← extKey1 (Lua initResponse[9])
		strconv.FormatInt(sessionToken, 10),     // [9]
		serverProof,                             // [10]
		sessionURLToken,                         // [11]
		strconv.FormatInt(startHashInput, 10),   // [12]
		maxUsesLimitStr,                         // [13]
		strconv.FormatInt(totalUses, 10),        // [14]
		discordID,                               // [15]
	}

	// ── 7. Encode response with 4-byte key (clientTokens % 256) ─────────────
	fourKey := crypto.FourByteKey(clientToken1, clientToken2, clientToken3, clientToken4)
	respCipher := crypto.NewCipher(fourKey)
	encoded := respCipher.EncodeStrings(response)

	// ── 8. Persist the session ───────────────────────────────────────────────
	session := &db.Session{
		ScriptID:         scriptID,
		LicenseKey:       licenseKey,
		SessionToken:     sessionToken,
		SessionURLToken:  sessionURLToken,
		HWID:             hwid,
		Nonce2:           nonce2,
		ServerNonce2Init: sn2,
		ExtKey1:          extKey1,
		ExtKey3:          extKey3,
		ExtKey5:          extKey5,
		ExtKey7:          extKey7,
		CT1:              clientToken1 % 256,
		CT2:              clientToken2 % 256,
		CT3:              clientToken3 % 256,
		CT4:              clientToken4 % 256,
	}
	if err := db.CreateSession(session); err != nil {
		// Non-fatal: the response is already built. Log and continue.
		_ = err
	}

	w.Write([]byte(encoded))
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

func randInt64(min, max int64) int64 {
	diff := max - min + 1
	n, err := rand.Int(rand.Reader, big.NewInt(diff))
	if err != nil {
		return min
	}
	return min + n.Int64()
}

func randURLToken() string {
	b := make([]byte, 12)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// unused but kept for completeness
var _ = fmt.Sprintf
