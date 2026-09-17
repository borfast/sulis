// Command safari-cookies measures one fact that the README and cookie-name
// option docs currently only hedge about: which of sulis's session and CSRF
// cookies does real Safari keep when they are set over plain HTTP, on
// localhost and on 127.0.0.1?
//
// All four sulis cookies carry Secure, because sulis fixes that attribute on
// both cookie families. Renaming away from the __Host- prefix is therefore
// only useful for local development if Safari's objection is to the prefix
// and not to Secure itself. This program answers that instead of guessing.
//
// It is not part of the library build: the go tool skips directories whose
// name begins with a dot, so ./... never matches this file. CI runs it as
//
//	go run .github/safari/main.go
//
// with safaridriver already listening on driverAddr.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/borfast/sulis"
	"github.com/borfast/sulis/memstore"
)

const (
	serverPort               = "8099"
	driverAddr               = "http://127.0.0.1:4444"
	renamedCSRFCookieName    = "csrf_token"
	renamedSessionCookieName = "session"
	controlCookieName        = "sulis_control_not_secure"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "safari-cookies:", err)
		os.Exit(1)
	}
}

func run() error {
	// Build all four sulis cookies through the library itself, so this measures
	// the library rather than a hand-written imitation of it. No login is
	// needed: SessionCookie only formats the cookie, so a dummy token and
	// expiry are sufficient for this browser-storage probe.
	defaultAuth, err := sulis.New(
		memstore.NewUserStore(), memstore.NewSessionStore(), memstore.NewTokenStore(),
		sulis.NoSecondFactors{},
	)
	if err != nil {
		return fmt.Errorf("New default Sulis: %w", err)
	}
	_, defaultCSRFCookie, err := sulis.IssueCSRFToken()
	if err != nil {
		return fmt.Errorf("IssueCSRFToken: %w", err)
	}
	defaultSessionCookie := defaultAuth.SessionCookie("probe-session-token", time.Now().Add(time.Hour))

	renamedAuth, err := sulis.New(
		memstore.NewUserStore(), memstore.NewSessionStore(), memstore.NewTokenStore(),
		sulis.NoSecondFactors{},
		sulis.WithCookieName(renamedSessionCookieName),
		sulis.WithCSRFCookieName(renamedCSRFCookieName),
	)
	if err != nil {
		return fmt.Errorf("New renamed Sulis: %w", err)
	}
	_, renamedCSRFCookie, err := renamedAuth.IssueCSRFToken()
	if err != nil {
		return fmt.Errorf("(*Sulis).IssueCSRFToken: %w", err)
	}
	renamedSessionCookie := renamedAuth.SessionCookie("probe-session-token", time.Now().Add(time.Hour))

	// Control: same basic attributes as the four above except Secure. If Safari
	// drops all five, the session is rejecting cookies for some unrelated
	// reason and the other rows prove nothing.
	controlCookie := &http.Cookie{
		Name: controlCookieName, Value: "control", Path: "/",
		HttpOnly: false, Secure: false, SameSite: http.SameSiteLaxMode,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, defaultSessionCookie)
		http.SetCookie(w, renamedSessionCookie)
		http.SetCookie(w, defaultCSRFCookie)
		http.SetCookie(w, renamedCSRFCookie)
		http.SetCookie(w, controlCookie)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<!doctype html><title>sulis cookie probe</title><p>ok")
	})
	// All interfaces, not 127.0.0.1: on macOS "localhost" may resolve to ::1
	// first, and both spellings have to reach this server.
	srv := &http.Server{Addr: ":" + serverPort, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()

	if err := waitForDriver(); err != nil {
		return err
	}

	fmt.Printf("Safari: %s; macOS: %s; runner: %s\n", safariVersion(), macOSVersion(), runnerContext())
	fmt.Println("Informational probe: stored means Safari kept the cookie; dropped means it did not.")
	fmt.Printf("Cookie columns: default session=%q; renamed session=%q; default CSRF=%q; renamed CSRF=%q; control=%q\n",
		defaultSessionCookie.Name, renamedSessionCookie.Name,
		defaultCSRFCookie.Name, renamedCSRFCookie.Name, controlCookie.Name)
	fmt.Printf("%-26s  %-16s  %-16s  %-16s  %-16s  %s\n", "origin",
		"default session", "renamed session", "default CSRF", "renamed CSRF", "control (no Secure)")
	for _, host := range []string{"localhost", "127.0.0.1"} {
		origin := "http://" + host + ":" + serverPort
		stored, err := storedCookies(origin + "/")
		if err != nil {
			return fmt.Errorf("%s: %w", origin, err)
		}
		fmt.Printf("%-26s  %-16s  %-16s  %-16s  %-16s  %s\n", origin,
			kept(stored[defaultSessionCookie.Name]), kept(stored[renamedSessionCookie.Name]),
			kept(stored[defaultCSRFCookie.Name]), kept(stored[renamedCSRFCookie.Name]),
			kept(stored[controlCookie.Name]))
	}
	return nil
}

func kept(ok bool) string {
	if ok {
		return "stored"
	}
	return "dropped"
}

// storedCookies loads url in a fresh Safari session and reports which cookie
// names the browser actually kept. A fresh session is intentional: each host
// is measured independently, with no cookies carried over from the other.
func storedCookies(url string) (map[string]bool, error) {
	var session struct {
		Value struct {
			SessionID string `json:"sessionId"`
		} `json:"value"`
	}
	caps := map[string]any{
		"capabilities": map[string]any{
			"alwaysMatch": map[string]any{"browserName": "safari"},
		},
	}
	if err := call(http.MethodPost, "/session", caps, &session); err != nil {
		return nil, err
	}
	id := session.Value.SessionID
	if id == "" {
		return nil, fmt.Errorf("safaridriver returned no session id")
	}
	defer func() { _ = call(http.MethodDelete, "/session/"+id, nil, nil) }()

	if err := call(http.MethodPost, "/session/"+id+"/url", map[string]any{"url": url}, nil); err != nil {
		return nil, err
	}
	var jar struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := call(http.MethodGet, "/session/"+id+"/cookie", nil, &jar); err != nil {
		return nil, err
	}
	names := make(map[string]bool, len(jar.Value))
	for _, c := range jar.Value {
		names[c.Name] = true
	}
	return names, nil
}

func waitForDriver() error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := call(http.MethodGet, "/status", nil, nil); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("safaridriver did not answer on %s within 30s", driverAddr)
		}
		time.Sleep(time.Second)
	}
}

func macOSVersion() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return "unknown"
	}
	version := strings.TrimSpace(string(out))
	if version == "" {
		return "unknown"
	}
	return version
}

func safariVersion() string {
	out, err := exec.Command("safaridriver", "--version").CombinedOutput()
	if err != nil {
		return "unknown"
	}
	version := strings.TrimSpace(string(out))
	if version == "" {
		return "unknown"
	}
	return version
}

func runnerContext() string {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return "local"
	}
	osName := os.Getenv("RUNNER_OS")
	image := os.Getenv("ImageOS")
	imageVersion := os.Getenv("ImageVersion")
	parts := []string{osName}
	if image != "" {
		parts = append(parts, image)
	}
	if imageVersion != "" {
		parts = append(parts, imageVersion)
	}
	for i, part := range parts {
		if part == "" {
			parts[i] = "unknown"
		}
	}
	return strings.Join(parts, "/")
}

func call(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, driverAddr+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, raw)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}
