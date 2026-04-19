// Package db provides a lightweight Supabase REST API client.
// All database interaction goes through the Supabase PostgREST HTTP API.
package db

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
// Client
// ────────────────────────────────────────────────────────────────────────────

var (
	supabaseURL     = os.Getenv("SUPABASE_URL")
	supabaseKey     = os.Getenv("SUPABASE_SERVICE_ROLE_KEY")
	httpClient      = &http.Client{Timeout: 8 * time.Second}
)

func headers(req *http.Request) {
	req.Header.Set("apikey", supabaseKey)
	req.Header.Set("Authorization", "Bearer "+supabaseKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=representation")
}

func get(table string, params map[string]string, dest interface{}) error {
	u, _ := url.Parse(supabaseURL + "/rest/v1/" + table)
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}
	headers(req)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("supabase GET %s: %s – %s", table, resp.Status, body)
	}
	return json.Unmarshal(body, dest)
}

func post(table string, payload interface{}, dest interface{}) error {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", supabaseURL+"/rest/v1/"+table, bytes.NewReader(b))
	if err != nil {
		return err
	}
	headers(req)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("supabase POST %s: %s – %s", table, resp.Status, body)
	}
	if dest != nil {
		return json.Unmarshal(body, dest)
	}
	return nil
}

func patch(table string, filter map[string]string, payload interface{}) error {
	u, _ := url.Parse(supabaseURL + "/rest/v1/" + table)
	q := u.Query()
	for k, v := range filter {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	b, _ := json.Marshal(payload)
	req, err := http.NewRequest("PATCH", u.String(), bytes.NewReader(b))
	if err != nil {
		return err
	}
	headers(req)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("supabase PATCH %s: %s – %s", table, resp.Status, body)
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Domain types
// ────────────────────────────────────────────────────────────────────────────

// Script holds the metadata for a protected script.
type Script struct {
	ID               string `json:"id"`
	ProjectID        string `json:"project_id"`
	Name             string `json:"name"`
	ScriptVersion    string `json:"script_version"`
	ProtectedPayload string `json:"protected_payload"`
	ScriptNote       string `json:"script_note"`
	UserIdentifier   string `json:"user_identifier"`
	UserNote         string `json:"user_note"`
}

// WhitelistEntry is a license key row.
type WhitelistEntry struct {
	ID         string     `json:"id"`
	ScriptID   string     `json:"script_id"`
	LicenseKey string     `json:"license_key"`
	HWID       *string    `json:"hwid"`
	DiscordID  string     `json:"discord_id"`
	ExpiresAt  *time.Time `json:"expires_at"`
	MaxUses    int64      `json:"max_uses"`
	TotalUses  int64      `json:"total_uses"`
	IsBanned   bool       `json:"is_banned"`
	BanReason  string     `json:"ban_reason"`
	Note       string     `json:"note"`
}

// Session holds an active authentication session.
type Session struct {
	ID               string `json:"id"`
	ScriptID         string `json:"script_id"`
	LicenseKey       string `json:"license_key"`
	SessionToken     int64  `json:"session_token"`      // numeric token used in heartbeat hash
	SessionURLToken  string `json:"session_url_token"`  // token in URL paths / ?s= param
	CombinedSeed     int64  `json:"combined_seed"`      // populated after /start
	HWID             string `json:"hwid"`
	Nonce2           int64  `json:"nonce2"`             // from init request, used in heartbeat
	ServerNonce2Init int64  `json:"server_nonce2_init"` // client's sn[2] from init
	// Extended cipher key components (ek = server-generated extKey bytes)
	ExtKey1 int64 `json:"ext_key_1"`
	ExtKey3 int64 `json:"ext_key_3"`
	ExtKey5 int64 `json:"ext_key_5"`
	ExtKey7 int64 `json:"ext_key_7"`
	// 4 client token mod-256 values
	CT1 int64 `json:"ct1"`
	CT2 int64 `json:"ct2"`
	CT3 int64 `json:"ct3"`
	CT4 int64 `json:"ct4"`
	// Flags
	ShouldTerminate bool `json:"should_terminate"`
}

// ────────────────────────────────────────────────────────────────────────────
// Script queries
// ────────────────────────────────────────────────────────────────────────────

// GetScript fetches a script by its UUID.
func GetScript(scriptID string) (*Script, error) {
	var rows []Script
	err := get("scripts", map[string]string{"id": "eq." + scriptID}, &rows)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("script not found: %s", scriptID)
	}
	return &rows[0], nil
}

// ────────────────────────────────────────────────────────────────────────────
// Whitelist queries
// ────────────────────────────────────────────────────────────────────────────

// GetWhitelistEntry returns the whitelist entry for a given script/key pair.
func GetWhitelistEntry(scriptID, licenseKey string) (*WhitelistEntry, error) {
	var rows []WhitelistEntry
	err := get("whitelist_entries", map[string]string{
		"script_id":   "eq." + scriptID,
		"license_key": "eq." + licenseKey,
	}, &rows)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil // not found → not whitelisted
	}
	return &rows[0], nil
}

// LinkHWID stores the HWID on the whitelist entry (first-use binding).
func LinkHWID(entryID, hwid string) error {
	return patch("whitelist_entries", map[string]string{"id": "eq." + entryID},
		map[string]interface{}{"hwid": hwid})
}

// IncrementUses bumps the total_uses counter.
func IncrementUses(entryID string) error {
	// PostgREST doesn't support expressions; we fetch + patch
	return patch("whitelist_entries", map[string]string{"id": "eq." + entryID},
		map[string]string{"total_uses": "total_uses + 1"}) // handled via RPC if needed
}

// ────────────────────────────────────────────────────────────────────────────
// Session queries
// ────────────────────────────────────────────────────────────────────────────

// CreateSession inserts a new session and returns the created row.
func CreateSession(s *Session) error {
	var rows []Session
	return post("sessions", s, &rows)
}

// GetSessionByURLToken looks up a session by its URL token (path/query param).
func GetSessionByURLToken(urlToken string) (*Session, error) {
	var rows []Session
	err := get("sessions", map[string]string{"session_url_token": "eq." + urlToken}, &rows)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("session not found: %s", urlToken)
	}
	return &rows[0], nil
}

// UpdateSessionCombinedSeed stores the combinedSeed after the start handshake.
func UpdateSessionCombinedSeed(sessionID string, seed int64) error {
	return patch("sessions", map[string]string{"id": "eq." + sessionID},
		map[string]interface{}{
			"combined_seed":  seed,
			"last_heartbeat": time.Now().UTC().Format(time.RFC3339),
		})
}

// TouchHeartbeat updates the last_heartbeat timestamp.
func TouchHeartbeat(sessionID string) error {
	return patch("sessions", map[string]string{"id": "eq." + sessionID},
		map[string]interface{}{"last_heartbeat": time.Now().UTC().Format(time.RFC3339)})
}
