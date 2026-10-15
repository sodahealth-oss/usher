package usher

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// User is an authenticated user.
type User struct {
	// Subject is the Entra object ID (oid), stable per user.
	Subject string `json:"subject"`
	Name    string `json:"name"`
	Email   string `json:"email"`

	// Groups are the Entra group object IDs from the ID token. They are the
	// groups assigned to the shared app registration that this person is in,
	// not every group they belong to. Endpoint checks use this list; the
	// login allowlist does not filter it down.
	Groups []string `json:"groups,omitempty"`

	// Dev reports a session created by the development bypass rather than by
	// Entra. Surfaced so the UI can say so out loud.
	Dev bool `json:"dev"`
}

// InAnyGroup reports whether the session includes at least one of ids.
func (u User) InAnyGroup(ids ...string) bool {
	return hasAnyGroup(u.Groups, ids)
}

// Config is the runtime configuration. App-specific identity (cookie names,
// route paths) comes from Provider. Secrets and environment-dependent flags
// stay here so they are never committed next to the JSON file.
type Config struct {
	Provider Provider

	// TenantID, ClientID and ClientSecret come from the Entra app
	// registration.
	TenantID     string
	ClientID     string
	ClientSecret string

	// RedirectURL must exactly match a redirect URI registered on the app.
	RedirectURL string

	// AllowedGroupIDs are the object IDs — not display names — of the groups
	// whose members may sign in. Membership of any one is enough. This is
	// the per-app gate: a shared Entra registration is assigned the union of
	// every consumer's groups, so Entra cannot say "this redirect URI is
	// engineers only".
	//
	// The app registration must emit "Groups assigned to the application"
	// rather than "All groups". With All groups, a user in more than roughly
	// 200 groups triggers Entra's overage behaviour: the groups claim is
	// dropped and replaced by _claim_names/_claim_sources pointing at Graph,
	// and this check then fails closed for exactly the most-connected people
	// in the tenant. Assign only the groups your apps care about; that makes
	// overage impossible for a handful of IDs.
	AllowedGroupIDs []string

	// CookieKey signs session cookies. Must be at least 32 bytes, and every
	// app should have its own. The MAC is also bound to the client ID and
	// cookie names, so a key reused across apps no longer lets one app's
	// cookie authenticate to another — but a shared key still means a
	// leak anywhere is a leak everywhere.
	CookieKey []byte

	// Secure marks cookies Secure. False only for plain-HTTP local
	// development.
	Secure bool

	// TTL bounds a session's life. Zero means 12 hours.
	TTL time.Duration

	// DevUser bypasses Entra entirely, minting a session for the named user
	// on any request. It exists so an app is demoable before the app
	// registration is provisioned, and it must never be set in a deployment
	// reachable by anyone else.
	DevUser string

	Logger *slog.Logger

	// PresentError writes an auth failure to the client. err is always a
	// value this package exports; wrap it into copy that names the app.
	// Nil uses [DefaultPresentError].
	PresentError func(http.ResponseWriter, *http.Request, error)
}

// Manager handles the OIDC dance and session cookies.
type Manager struct {
	cfg      Config
	settings Settings
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	log      *slog.Logger
	present  func(http.ResponseWriter, *http.Request, error)
}

const (
	defaultTTL = 12 * time.Hour
	stateTTL   = 10 * time.Minute
	minKeyLen  = 32
)

// New builds a Manager. When cfg.DevUser is set, Entra is not contacted and
// the returned Manager authenticates everyone as that user.
func New(ctx context.Context, cfg Config) (*Manager, error) {
	if cfg.Provider == nil {
		return nil, ErrProviderRequired
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if len(cfg.CookieKey) < minKeyLen {
		return nil, fmt.Errorf("%w, got %d", ErrCookieKeyTooShort, len(cfg.CookieKey))
	}
	if cfg.TTL == 0 {
		cfg.TTL = defaultTTL
	}

	settings, err := cfg.Provider.Load()
	if err != nil {
		return nil, err
	}
	// File.Load already defaults and validates; doing it again here is
	// idempotent and covers custom Providers, which otherwise could return
	// colliding cookie names or paths that only fail at request time.
	settings = settings.withDefaults()
	if err := settings.validate(); err != nil {
		return nil, err
	}

	present := cfg.PresentError
	if present == nil {
		present = DefaultPresentError
	}

	m := &Manager{cfg: cfg, settings: settings, log: cfg.Logger, present: present}
	if cfg.DevUser != "" {
		// The bypass authenticates every request as one user, so a stray
		// development setting on a real deployment publishes the app to
		// anyone who finds the URL. Two conditions make that combination
		// refuse to start rather than warn:
		//
		// Secure cookies mean HTTPS, which means this is not a laptop.
		if cfg.Secure {
			return nil, ErrDevBypassSecure
		}
		// And a configured Entra app means somebody intended real
		// authentication, so the two settings contradict each other.
		if cfg.TenantID != "" || cfg.ClientID != "" || cfg.ClientSecret != "" || hasGroupID(cfg.AllowedGroupIDs) {
			return nil, ErrDevBypassWithEntra
		}
		m.log.Warn("development authentication bypass is active; every request is authenticated",
			"user", cfg.DevUser)
		return m, nil
	}

	for name, v := range map[string]string{
		"tenant ID": cfg.TenantID, "client ID": cfg.ClientID,
		"client secret": cfg.ClientSecret, "redirect URL": cfg.RedirectURL,
	} {
		if v == "" {
			return nil, &MissingFieldError{Field: name}
		}
	}
	if err := requireGroupIDs("allowed group IDs", cfg.AllowedGroupIDs); err != nil {
		return nil, err
	}

	issuer := "https://login.microsoftonline.com/" + cfg.TenantID + "/v2.0"
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("usher: discover Entra at %s: %w", issuer, err)
	}

	m.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	m.oauth = &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return m, nil
}

// DevMode reports whether the Entra flow is bypassed.
func (m *Manager) DevMode() bool { return m.cfg.DevUser != "" }

// SessionCookieName is the cookie a caller must set to be authenticated.
func (m *Manager) SessionCookieName() string { return m.settings.SessionCookie }

// Routes registers the authentication endpoints on mux.
func (m *Manager) Routes(mux Router) {
	mux.Get(m.settings.LoginPath, m.handleLogin)
	mux.Get(m.settings.CallbackPath, m.handleCallback)
	mux.Post(m.settings.LogoutPath, m.handleLogout)
}

// Router is the slice of an HTTP mux this package needs, kept as an
// interface so the package does not depend on chi.
type Router interface {
	Get(pattern string, h http.HandlerFunc)
	Post(pattern string, h http.HandlerFunc)
}

type ctxKey struct{}

// UserFrom returns the authenticated user carried on a request context.
func UserFrom(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(ctxKey{}).(User)
	return u, ok
}

// Require rejects unauthenticated requests. It answers 401 rather than
// redirecting, because every route behind it is an API the frontend calls;
// the frontend decides when to send someone to the login path.
func (m *Manager) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.DevMode() {
			u := User{Subject: "dev", Name: m.cfg.DevUser, Email: m.cfg.DevUser, Dev: true}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
			return
		}
		u, err := m.readSession(r)
		if err != nil {
			m.present(w, r, ErrUnauthenticated)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	})
}

// RequireAnyGroup is [Require] plus a group check. The session must include
// at least one of ids. Unauthenticated requests are 401; authenticated
// requests that miss the list are 403 via [GroupDeniedError].
//
// This is the per-route gate. The login allowlist is the per-app gate: a
// signed-in user has already passed AllowedGroupIDs. Use this when some
// endpoints are narrower than the app (engineers can mutate, product can
// read). An empty ids list fails closed.
//
// The development bypass skips the group check, matching [Require].
func (m *Manager) RequireAnyGroup(ids ...string) func(http.Handler) http.Handler {
	required := append([]string(nil), ids...)
	return func(next http.Handler) http.Handler {
		return m.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := UserFrom(r.Context())
			if !ok {
				m.present(w, r, ErrUnauthenticated)
				return
			}
			if m.DevMode() || u.InAnyGroup(required...) {
				next.ServeHTTP(w, r)
				return
			}
			m.present(w, r, &GroupDeniedError{
				Subject:       u.Subject,
				GroupIDs:      required,
				GroupsInToken: len(u.Groups),
			})
		}))
	}
}

// handleLogin starts the authorization code flow.
func (m *Manager) handleLogin(w http.ResponseWriter, r *http.Request) {
	if m.DevMode() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	verifier := oauth2.GenerateVerifier()
	state, err := randomString()
	if err != nil {
		m.log.Error("generate state", "err", err)
		m.present(w, r, ErrInternal)
		return
	}

	// The verifier and state ride in a short-lived signed cookie rather than
	// server memory, so a login survives a restart, a scale-to-zero sleep, or
	// a callback that lands on a different replica.
	payload, err := m.seal(kindState,
		pending{State: state, Verifier: verifier, Return: safeReturn(r.URL.Query().Get("return"))},
		stateTTL)
	if err != nil {
		m.log.Error("seal oidc state", "err", err)
		m.present(w, r, ErrInternal)
		return
	}
	m.setCookie(w, m.settings.StateCookie, payload, stateTTL)

	http.Redirect(w, r, m.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// handleCallback completes the flow and issues a session.
func (m *Manager) handleCallback(w http.ResponseWriter, r *http.Request) {
	if m.DevMode() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if errCode := r.URL.Query().Get("error"); errCode != "" {
		// Entra's error_description can contain user-identifying detail, so
		// only the AADSTS code is logged.
		m.log.Warn("entra returned an error", "error", errCode,
			"error_code", entraErrorCode(r.URL.Query().Get("error_description")))
		m.present(w, r, ErrSignInFailed)
		return
	}

	c, err := r.Cookie(m.settings.StateCookie)
	if err != nil {
		m.present(w, r, ErrSignInExpired)
		return
	}
	m.clearCookie(w, m.settings.StateCookie)

	var p pending
	if err := m.open(kindState, c.Value, &p); err != nil {
		m.present(w, r, ErrSignInExpired)
		return
	}
	// An empty stored state would match an empty ?state=, so require both to
	// be present before comparing. Constant-time thereafter: a mismatch is a
	// CSRF attempt, not a typo.
	got := r.URL.Query().Get("state")
	if p.State == "" || got == "" ||
		subtle.ConstantTimeCompare([]byte(p.State), []byte(got)) != 1 {
		m.present(w, r, ErrInvalidState)
		return
	}

	token, err := m.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(p.Verifier))
	if err != nil {
		m.log.Warn("token exchange failed", "err", err)
		m.present(w, r, ErrSignInFailed)
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		m.present(w, r, ErrSignInFailed)
		return
	}
	idToken, err := m.verifier.Verify(r.Context(), rawID)
	if err != nil {
		m.log.Warn("id token rejected", "err", err)
		m.present(w, r, ErrSignInFailed)
		return
	}

	var claims struct {
		OID    string   `json:"oid"`
		Name   string   `json:"name"`
		Email  string   `json:"preferred_username"`
		Groups []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		m.log.Warn("id token claims unreadable", "err", err)
		m.present(w, r, ErrSignInFailed)
		return
	}

	if denied := groupDenied(claims.OID, claims.Groups, m.cfg.AllowedGroupIDs); denied != nil {
		// An empty groups claim on a user who is genuinely in an allowed
		// group means the app registration is emitting "All groups" and
		// overage has kicked in. Say so in the log, because the symptom is
		// otherwise indistinguishable from a permissions problem.
		m.log.Warn("sign-in denied: required group absent from token",
			"subject", denied.Subject, "groups_in_token", denied.GroupsInToken)
		m.present(w, r, denied)
		return
	}

	user := User{Subject: claims.OID, Name: claims.Name, Email: claims.Email, Groups: claims.Groups}
	payload, err := m.seal(kindSession, user, m.cfg.TTL)
	if err != nil {
		m.log.Error("seal session", "err", err)
		m.present(w, r, ErrInternal)
		return
	}
	m.setCookie(w, m.settings.SessionCookie, payload, m.cfg.TTL)
	m.log.Info("signed in", "subject", user.Subject)

	// Re-validated on the way out as well as on the way in. The cookie is
	// signed, so this cannot currently be reached with a hostile value — but
	// it makes the redirect safe by construction rather than by an invariant
	// held somewhere else in the file.
	http.Redirect(w, r, safeReturn(p.Return), http.StatusFound)
}

// handleLogout clears the session cookie. POST-only: a GET would let a
// third-party page sign people out with an <img> tag. POST alone still
// leaves an auto-submitting cross-site form, and this handler needs no
// cookie to have its effect, so it also refuses requests a browser marks as
// cross-origin. Requests without either header (curl, tests) pass — the
// check targets browsers, which always send Sec-Fetch-Site.
func (m *Manager) handleLogout(w http.ResponseWriter, r *http.Request) {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || !strings.EqualFold(u.Host, r.Host) {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
	}
	m.clearCookie(w, m.settings.SessionCookie)
	w.WriteHeader(http.StatusNoContent)
}

// readSession validates and decodes the session cookie.
func (m *Manager) readSession(r *http.Request) (User, error) {
	c, err := r.Cookie(m.settings.SessionCookie)
	if err != nil {
		return User{}, err
	}
	var u User
	if err := m.open(kindSession, c.Value, &u); err != nil {
		return User{}, err
	}
	return u, nil
}

// pending is the state carried across the authorization redirect.
type pending struct {
	State    string `json:"s"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
}

// Cookie kinds. Both cookies are signed with the same key, so without a kind
// inside the signed payload they are interchangeable — and one of them is
// handed to anyone who asks.
//
// The login path issues a state cookie before the caller has proved anything.
// Presenting that cookie under the session name would otherwise present a
// correctly-signed, unexpired envelope whose JSON body happens to decode into
// an all-empty User, and Require would admit it. That is a complete
// authentication bypass with no credential involved, so the kind is checked on
// every open.
const (
	kindSession = "session"
	kindState   = "state"
)

// envelope is the signed cookie payload.
type envelope struct {
	Kind    string          `json:"k"`
	Expires int64           `json:"exp"`
	Data    json.RawMessage `json:"d"`
}

// seal encodes v into a signed, expiring cookie value of the given kind.
func (m *Manager) seal(kind string, v any, ttl time.Duration) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(envelope{
		Kind:    kind,
		Expires: time.Now().Add(ttl).Unix(),
		Data:    data,
	})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(body)
	return enc + "." + base64.RawURLEncoding.EncodeToString(m.sign(kind, []byte(enc))), nil
}

// open verifies a cookie value's signature, kind and expiry, then decodes into
// v. A cookie of any other kind is rejected even though its signature is
// valid.
func (m *Manager) open(kind, value string, v any) error {
	encoded, sig, ok := strings.Cut(value, ".")
	if !ok {
		return ErrMalformedCookie
	}
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return ErrMalformedCookie
	}
	// Verify before decoding: never parse attacker-controlled JSON that has
	// not been authenticated.
	if !hmac.Equal(want, m.sign(kind, []byte(encoded))) {
		return ErrBadSignature
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return ErrMalformedCookie
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return ErrMalformedCookie
	}
	if env.Kind != kind {
		return fmt.Errorf("%w %q, want %q", ErrWrongCookieKind, env.Kind, kind)
	}
	if time.Now().Unix() >= env.Expires {
		return ErrExpiredCookie
	}
	return json.Unmarshal(env.Data, v)
}

// sign MACs a cookie payload bound to this app's identity as well as the key.
// The context prefix is the client ID and the kind's cookie name, so a cookie
// sealed by one consumer is worthless to another even when an operator reuses
// a CookieKey across apps — without it, a user who signed into app A
// could present A's cookie under app B's session name and pass B's Require
// without ever facing B's group allowlist. The cookie name carries the
// distinction when several apps share one Entra registration (one client ID),
// which the README describes; settings validation keeps names non-empty and
// control-free, so the 0x1f separators are unambiguous.
func (m *Manager) sign(kind string, b []byte) []byte {
	mac := hmac.New(sha256.New, m.cfg.CookieKey)
	mac.Write([]byte(m.cfg.ClientID))
	mac.Write([]byte{0x1f})
	mac.Write([]byte(m.cookieFor(kind)))
	mac.Write([]byte{0x1f})
	mac.Write(b)
	return mac.Sum(nil)
}

// cookieFor names the cookie a payload of the given kind rides in.
func (m *Manager) cookieFor(kind string) string {
	if kind == kindState {
		return m.settings.StateCookie
	}
	return m.settings.SessionCookie
}

func (m *Manager) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   m.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (m *Manager) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func hasGroupID(ids []string) bool {
	for _, id := range ids {
		if id != "" {
			return true
		}
	}
	return false
}

func requireGroupIDs(field string, ids []string) error {
	if len(ids) == 0 {
		return &MissingFieldError{Field: field}
	}
	for i, id := range ids {
		if id == "" {
			return &MissingFieldError{Field: fmt.Sprintf("%s[%d]", field, i)}
		}
	}
	return nil
}

func groupDenied(subject string, have, need []string) *GroupDeniedError {
	if hasAnyGroup(have, need) {
		return nil
	}
	return &GroupDeniedError{
		Subject:       subject,
		GroupIDs:      append([]string(nil), need...),
		GroupsInToken: len(have),
	}
}

func hasAnyGroup(have, need []string) bool {
	for _, id := range need {
		if id != "" && slices.Contains(have, id) {
			return true
		}
	}
	return false
}

// randomString produces an unguessable token.
func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// safeReturn restricts post-login redirects to paths within this app.
//
// An unchecked return parameter is an open redirect, and the sign-in page is
// the worst place to have one: the victim really is on the app's domain when
// they click, so the usual "check the address bar" advice does not help them.
//
// Three things have to be rejected, and only the first is obvious:
//
//   - an absolute URL, which needs no explanation;
//   - "//host" and "/\host", both of which a browser resolves as
//     protocol-relative — the backslash form passes a naive "starts with a
//     single slash" check;
//   - anything containing a control character, because browsers strip those
//     before resolving, so "/\t//host" becomes "///host" after the check has
//     already approved it.
func safeReturn(v string) string {
	if v == "" || !strings.HasPrefix(v, "/") {
		return "/"
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" {
		return "/"
	}
	// Everything below is checked against the *decoded* path, so a
	// percent-encoded separator cannot smuggle a host past the prefix tests:
	// "/%09//host" decodes to "/\t//host", which a browser strips to "///host".
	for _, r := range u.Path {
		if r < 0x20 || r == 0x7f {
			return "/"
		}
	}
	if !strings.HasPrefix(u.Path, "/") ||
		strings.HasPrefix(u.Path, "//") ||
		strings.HasPrefix(u.Path, `/\`) {
		return "/"
	}
	// Rebuild from the parsed pieces: whatever host-like text was in the
	// input cannot survive this.
	return u.RequestURI()
}
