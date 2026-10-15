package usher

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSettingsFile(t *testing.T, s Settings) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.json")
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestFileLoadRoundTrip(t *testing.T) {
	want := Settings{
		SessionCookie: "app_session",
		StateCookie:   "app_oidc_state",
		LoginPath:     "/signin",
		CallbackPath:  "/signin/callback",
		LogoutPath:    "/signin/logout",
	}
	got, err := File{Path: writeSettingsFile(t, want)}.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Errorf("Load = %+v, want %+v", got, want)
	}
}

func TestFileLoadFillsDefaultPaths(t *testing.T) {
	got, err := File{Path: writeSettingsFile(t, Settings{
		SessionCookie: "app_session",
		StateCookie:   "app_oidc_state",
	})}.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.LoginPath != defaultLoginPath || got.CallbackPath != defaultCallbackPath || got.LogoutPath != defaultLogoutPath {
		t.Errorf("paths = %+v", got)
	}
}

func TestFileLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, []byte(`{"sessionCookie":"a","stateCookie":"b","prompt":"consent"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := (File{Path: path}).Load(); err == nil {
		t.Fatal("Load accepted an unknown field")
	}
}

func TestFileLoadRejectsMissingCookieNames(t *testing.T) {
	_, err := File{Path: writeSettingsFile(t, Settings{SessionCookie: "app_session"})}.Load()
	var missing *MissingFieldError
	if !errors.As(err, &missing) || missing.Field != "stateCookie" {
		t.Fatalf("err = %v, want MissingFieldError{stateCookie}", err)
	}
}

func TestFileLoadRejectsIdenticalCookieNames(t *testing.T) {
	_, err := File{Path: writeSettingsFile(t, Settings{
		SessionCookie: "same",
		StateCookie:   "same",
	})}.Load()
	if err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("err = %v, want cookie names must differ", err)
	}
}

func TestFileLoadRejectsAbsoluteLoginPath(t *testing.T) {
	_, err := File{Path: writeSettingsFile(t, Settings{
		SessionCookie: "app_session",
		StateCookie:   "app_oidc_state",
		LoginPath:     "https://evil.example/login",
	})}.Load()
	if err == nil {
		t.Fatal("Load accepted a non-root-relative loginPath")
	}
}

func TestFileLoadMissingFile(t *testing.T) {
	_, err := (File{Path: filepath.Join(t.TempDir(), "nope.json")}).Load()
	if err == nil {
		t.Fatal("Load succeeded for a missing file")
	}
}

func TestFileLoadEmptyPath(t *testing.T) {
	if _, err := (File{}).Load(); err == nil {
		t.Fatal("Load succeeded with an empty path")
	}
}
