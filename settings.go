package usher

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// Provider loads the consuming application's identity for this package:
// cookie names, route paths, and anything else that must not be hardcoded
// here. Secrets do not belong on a Provider; they stay on [Config].
type Provider interface {
	Load() (Settings, error)
}

// Settings are the pieces of configuration that vary between consuming apps
// and are safe to keep in a file.
type Settings struct {
	// SessionCookie and StateCookie must be distinct, valid cookie names.
	// They are how two apps on the same parent domain avoid clobbering each
	// other, and how a state cookie is prevented from being presented as a
	// session — the kind check inside the signed payload is the real defence,
	// but distinct names keep the two cookies from colliding in the browser.
	SessionCookie string `json:"sessionCookie"`
	StateCookie   string `json:"stateCookie"`

	// LoginPath, CallbackPath and LogoutPath are the routes [Manager.Routes]
	// registers. Empty values become /auth/login, /auth/callback and
	// /auth/logout.
	LoginPath    string `json:"loginPath"`
	CallbackPath string `json:"callbackPath"`
	LogoutPath   string `json:"logoutPath"`
}

const (
	defaultLoginPath    = "/auth/login"
	defaultCallbackPath = "/auth/callback"
	defaultLogoutPath   = "/auth/logout"
)

func (s Settings) withDefaults() Settings {
	if s.LoginPath == "" {
		s.LoginPath = defaultLoginPath
	}
	if s.CallbackPath == "" {
		s.CallbackPath = defaultCallbackPath
	}
	if s.LogoutPath == "" {
		s.LogoutPath = defaultLogoutPath
	}
	return s
}

func (s Settings) validate() error {
	if err := validCookieName("sessionCookie", s.SessionCookie); err != nil {
		return err
	}
	if err := validCookieName("stateCookie", s.StateCookie); err != nil {
		return err
	}
	if s.SessionCookie == s.StateCookie {
		return fmt.Errorf("usher: sessionCookie and stateCookie must differ")
	}
	for _, f := range []struct{ name, v string }{
		{"loginPath", s.LoginPath},
		{"callbackPath", s.CallbackPath},
		{"logoutPath", s.LogoutPath},
	} {
		if err := validPath(f.name, f.v); err != nil {
			return err
		}
	}
	if s.LoginPath == s.CallbackPath || s.LoginPath == s.LogoutPath || s.CallbackPath == s.LogoutPath {
		return fmt.Errorf("usher: loginPath, callbackPath and logoutPath must differ")
	}
	return nil
}

func validCookieName(field, name string) error {
	if name == "" {
		return &MissingFieldError{Field: field}
	}
	// http.Cookie.Valid checks more than the name, so feed it a dummy value
	// that satisfies the value rules; we only care whether the name is legal.
	if err := (&http.Cookie{Name: name, Value: "x"}).Valid(); err != nil {
		return fmt.Errorf("usher: %s %q is not a valid cookie name: %w", field, name, err)
	}
	return nil
}

func validPath(field, path string) error {
	if path == "" {
		return &MissingFieldError{Field: field}
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return fmt.Errorf("usher: %s must be a root-relative path, got %q", field, path)
	}
	return nil
}

// File is a [Provider] that reads [Settings] from a JSON file.
type File struct {
	Path string
}

// Load decodes Settings from the file at Path. Unknown fields are rejected
// so a typo cannot silently fall back to a default.
func (f File) Load() (Settings, error) {
	if f.Path == "" {
		return Settings{}, fmt.Errorf("usher: config file path is empty")
	}
	raw, err := os.ReadFile(f.Path)
	if err != nil {
		return Settings{}, fmt.Errorf("usher: read config %s: %w", f.Path, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var s Settings
	if err := dec.Decode(&s); err != nil {
		return Settings{}, fmt.Errorf("usher: parse config %s: %w", f.Path, err)
	}
	s = s.withDefaults()
	if err := s.validate(); err != nil {
		return Settings{}, err
	}
	return s, nil
}
