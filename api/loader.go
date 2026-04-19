// api/loader.go
// GET /files/{version}/loaders/{script_id}.lua
//
// If the request comes from a browser (not Roblox), returns an HTML preview page.
// If the request comes from Roblox (User-Agent contains "Roblox"), returns the
// actual Lua loader script that bootstraps the SpideyAuth client.
//
// Routed via vercel.json: /files/:version/loaders/:script_id.lua → /api/loader?script_id=$script_id
package handler

import (
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/spideyauth/backend/pkg/db"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	scriptID := r.URL.Query().Get("script_id")
	if scriptID == "" {
		http.Error(w, "Missing script_id", http.StatusBadRequest)
		return
	}

	ua := r.Header.Get("User-Agent")
	isRoblox := strings.Contains(ua, "Roblox") || strings.Contains(ua, "roblox")

	if !isRoblox {
		renderHTMLPreview(w, r, scriptID)
		return
	}

	renderLuaLoader(w, r, scriptID)
}

// ────────────────────────────────────────────────────────────────────────────
// Lua loader
// ────────────────────────────────────────────────────────────────────────────

func renderLuaLoader(w http.ResponseWriter, r *http.Request, scriptID string) {
	script, err := db.GetScript(scriptID)
	if err != nil || script == nil {
		http.Error(w, "Script not found", http.StatusNotFound)
		return
	}

	// Determine the base URL for self-referencing
	scheme := "https"
	host := r.Host
	if r.TLS == nil && !strings.Contains(host, ".vercel.app") {
		scheme = "http"
	}
	baseURL := scheme + "://" + host

	loader := buildLuaLoader(scriptID, baseURL, script.ScriptVersion)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write([]byte(loader))
}

func buildLuaLoader(scriptID, baseURL, _ string) string {
	return fmt.Sprintf(`-- SpideyAuth Loader (generated %s)
-- Load via: loadstring(game:HttpGet(%q))()

local SpideyAuthConfig = {
    Host = %q,
    ScriptID = %q,
}

-- Inject config and execute the auth client
local src = game:HttpGet(SpideyAuthConfig.Host .. "/files/v1/client.lua")
loadstring(src)(SpideyAuthConfig)
`,
		time.Now().Format(time.RFC3339),
		baseURL+"/files/v1/loaders/"+scriptID+".lua",
		baseURL,
		scriptID,
	)
}

// ────────────────────────────────────────────────────────────────────────────
// HTML preview (served to browsers)
// ────────────────────────────────────────────────────────────────────────────

func renderHTMLPreview(w http.ResponseWriter, r *http.Request, scriptID string) {
	scheme := "https"
	host := r.Host
	if r.TLS == nil && !strings.Contains(host, ".vercel.app") {
		scheme = "http"
	}
	loaderURL := fmt.Sprintf("%s://%s/files/v1/loaders/%s.lua", scheme, host, scriptID)

	safeID := html.EscapeString(scriptID)
	safeURL := html.EscapeString(loaderURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, previewHTML, safeID, safeURL, safeURL)
}

const previewHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SpideyAuth Loader – %s</title>
<style>
  :root {
    --bg: #0f1117;
    --surface: #1a1d27;
    --border: #2d3148;
    --accent: #6c63ff;
    --text: #e2e8f0;
    --muted: #8892b0;
    --code-bg: #0a0c14;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 2rem;
  }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    max-width: 680px;
    width: 100%%;
    padding: 2.5rem;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(108,99,255,0.15);
    border: 1px solid rgba(108,99,255,0.3);
    color: var(--accent);
    padding: 4px 12px;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    margin-bottom: 1.5rem;
  }
  h1 { font-size: 1.6rem; font-weight: 700; margin-bottom: 0.5rem; }
  .script-id { color: var(--muted); font-size: 0.9rem; margin-bottom: 2rem; font-family: monospace; }
  .section-label {
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 0.6rem;
  }
  .code-block {
    background: var(--code-bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.25rem;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 0.875rem;
    color: #a8ff78;
    word-break: break-all;
    margin-bottom: 1.25rem;
    position: relative;
  }
  .copy-btn {
    position: absolute;
    top: 0.5rem;
    right: 0.5rem;
    background: var(--border);
    border: none;
    color: var(--muted);
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 0.75rem;
    cursor: pointer;
    transition: all 0.2s;
  }
  .copy-btn:hover { background: var(--accent); color: #fff; }
  .info-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-top: 1.5rem;
  }
  .info-item {
    background: var(--code-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.75rem 1rem;
  }
  .info-item .label { font-size: 0.7rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .info-item .value { font-size: 0.9rem; margin-top: 2px; }
  footer { text-align: center; margin-top: 2rem; color: var(--muted); font-size: 0.8rem; }
</style>
</head>
<body>
<div class="card">
  <div class="badge">⚡ SpideyAuth v3.4</div>
  <h1>Loader Preview</h1>
  <p class="script-id">Script ID: %s</p>

  <p class="section-label">Roblox loadstring</p>
  <div class="code-block">
    loadstring(game:HttpGet(%q))()
    <button class="copy-btn" onclick="navigator.clipboard.writeText(document.querySelector('.code-block').innerText.replace('Copy','').trim());this.textContent='Copied!'">Copy</button>
  </div>

  <div class="info-grid">
    <div class="info-item">
      <div class="label">Protocol</div>
      <div class="value">SpideyAuth v3.4</div>
    </div>
    <div class="info-item">
      <div class="label">Transport</div>
      <div class="value">WebSocket + HTTP</div>
    </div>
    <div class="info-item">
      <div class="label">Heartbeat</div>
      <div class="value">Every 20 seconds</div>
    </div>
    <div class="info-item">
      <div class="label">HWID Lock</div>
      <div class="value">Enabled</div>
    </div>
  </div>
</div>
<footer>Powered by SpideyAuth</footer>
</body>
</html>`