package usher

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const key = "0123456789abcdef0123456789abcdef"

func testSettings() Settings {
	return Settings{
		SessionCookie: "app_session",
		StateCookie:   "app_oidc_state",
		LoginPath:     "/auth/login",
		CallbackPath:  "/auth/callback",
		LogoutPath:    "/auth/logout",
	}
}

func testProvider(t *testing.T) Provider {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.json")
	raw, err := json.Marshal(testSettings())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return File{Path: path}
}

// manager builds a Manager without contacting Entra, so the cookie and
// middleware behaviour can be tested on its own.
func manager(t *testing.T) *Manager {
	t.Helper()
	return &Manager{
		cfg:      Config{CookieKey: []byte(key), TTL: time.Hour, Logger: quiet()},
		settings: testSettings(),
		log:      quiet(),
		present:  DefaultPresentError,
	}
}

func TestNewRejectsWeakCookieKey(t *testing.T) {
	// A short key is a forgeable key, and the failure is silent otherwise.
	_, err := New(t.Context(), Config{Provider: testProvider(t), CookieKey: []byte("tooshort"), DevUser: "x"})
	if !errors.Is(err, ErrCookieKeyTooShort) {
		t.Errorf("short cookie key: err = %v, want ErrCookieKeyTooShort", err)
	}
	if _, err := New(t.Context(), Config{Provider: testProvider(t), CookieKey: []byte(key), DevUser: "x", Logger: quiet()}); err != nil {
		t.Errorf("valid dev config rejected: %v", err)
	}
}

func TestNewRequiresProvider(t *testing.T) {
	_, err := New(t.Context(), Config{CookieKey: []byte(key), DevUser: "x", Logger: quiet()})
	if !errors.Is(err, ErrProviderRequired) {
		t.Errorf("err = %v, want ErrProviderRequired", err)
	}
}

func TestNewRequiresEntraSettingsOutsideDevMode(t *testing.T) {
	// Without DevUser the manager must not start half-configured: a missing
	// group ID would mean no authorization gate at all.
	_, err := New(t.Context(), Config{Provider: testProvider(t), CookieKey: []byte(key), Logger: quiet()})
	if err == nil {
		t.Fatal("New succeeded with no Entra settings and no dev bypass")
	}
	var missing *MissingFieldError
	if !errors.As(err, &missing) {
		t.Errorf("error %q is not MissingFieldError", err)
	}
}

func usersEqual(a, b User) bool {
	return a.Subject == b.Subject && a.Name == b.Name && a.Email == b.Email && a.Dev == b.Dev && slices.Equal(a.Groups, b.Groups)
}

func TestSealOpenRoundTrip(t *testing.T) {
	m := manager(t)
	want := User{Subject: "oid-123", Name: "Ada", Email: "ada@example.com", Groups: []string{"engineers", "product"}}

	sealed, err := m.seal(kindSession, want, time.Hour)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	var got User
	if err := m.open(kindSession, sealed, &got); err != nil {
		t.Fatalf("open: %v", err)
	}
	if !usersEqual(got, want) {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}

func TestOpenRejectsTamperedCookies(t *testing.T) {
	m := manager(t)
	sealed, err := m.seal(kindSession, User{Subject: "oid-123"}, time.Hour)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	payload, sig, _ := strings.Cut(sealed, ".")

	for name, value := range map[string]string{
		"empty":               "",
		"no separator":        payload,
		"payload swapped":     mustSeal(t, m, User{Subject: "attacker"}, time.Hour).payload + "." + sig,
		"signature dropped":   payload + ".",
		"signature garbage":   payload + ".AAAA",
		"signature truncated": payload + "." + sig[:len(sig)-4],
		"both empty":          ".",
		"not base64":          "!!!.???",
	} {
		var u User
		if err := m.open(kindSession, value, &u); err == nil {
			t.Errorf("%s: open accepted a bad cookie and produced %+v", name, u)
		}
	}
}

type sealed struct{ payload, sig string }

func mustSeal(t *testing.T, m *Manager, u User, ttl time.Duration) sealed {
	t.Helper()
	s, err := m.seal(kindSession, u, ttl)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	p, sig, _ := strings.Cut(s, ".")
	return sealed{p, sig}
}

func TestOpenRejectsAnotherKeysCookie(t *testing.T) {
	// Rotating the cookie key must invalidate every outstanding session.
	issuer := manager(t)
	other := &Manager{
		cfg:      Config{CookieKey: []byte("ffffffffffffffffffffffffffffffff"), TTL: time.Hour},
		settings: testSettings(),
		log:      quiet(),
		present:  DefaultPresentError,
	}
	cookie, err := issuer.seal(kindSession, User{Subject: "oid-123"}, time.Hour)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	var u User
	if err := other.open(kindSession, cookie, &u); err == nil {
		t.Error("a cookie signed with a different key was accepted")
	}
}

func TestOpenRejectsExpiredCookies(t *testing.T) {
	m := manager(t)
	cookie, err := m.seal(kindSession, User{Subject: "oid-123"}, -time.Second)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	var u User
	if err := m.open(kindSession, cookie, &u); err == nil {
		t.Error("an expired cookie was accepted")
	}
}

func TestRequireRejectsUnauthenticatedRequests(t *testing.T) {
	m := manager(t)
	var reached bool
	h := m.Require(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/pulls", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if reached {
		t.Error("the handler ran for an unauthenticated request")
	}
}

func TestRequirePassesTheUserThrough(t *testing.T) {
	m := manager(t)
	want := User{Subject: "oid-123", Name: "Ada"}
	cookie, err := m.seal(kindSession, want, time.Hour)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	var got User
	var ok bool
	h := m.Require(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, ok = UserFrom(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/pulls", nil)
	req.AddCookie(&http.Cookie{Name: m.SessionCookieName(), Value: cookie})
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !ok || !usersEqual(got, want) {
		t.Errorf("user in context = %+v (ok=%v), want %+v", got, ok, want)
	}
}

func TestRequireInDevModeAuthenticatesEveryone(t *testing.T) {
	m := &Manager{
		cfg:      Config{CookieKey: []byte(key), DevUser: "dev@example.com"},
		settings: testSettings(),
		log:      quiet(),
		present:  DefaultPresentError,
	}

	var got User
	h := m.Require(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = UserFrom(r.Context())
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/pulls", nil))

	if !got.Dev {
		t.Error("Dev is false; the UI has no way to warn that the bypass is on")
	}
	if got.Name != "dev@example.com" {
		t.Errorf("name = %q", got.Name)
	}
	if !m.DevMode() {
		t.Error("DevMode() = false")
	}
}

func TestLogoutClearsTheCookie(t *testing.T) {
	m := manager(t)
	rec := httptest.NewRecorder()
	m.handleLogout(rec, httptest.NewRequest(http.MethodPost, "/auth/logout", nil))

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == m.SessionCookieName() && c.MaxAge < 0 && c.Value == "" {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the session cookie was not cleared")
	}
}

func TestCookieFlags(t *testing.T) {
	m := &Manager{
		cfg:      Config{CookieKey: []byte(key), Secure: true, TTL: time.Hour},
		settings: testSettings(),
		log:      quiet(),
		present:  DefaultPresentError,
	}
	rec := httptest.NewRecorder()
	m.setCookie(rec, m.SessionCookieName(), "value", time.Hour)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies", len(cookies))
	}
	c := cookies[0]
	if !c.HttpOnly {
		t.Error("HttpOnly is false; script can read the session")
	}
	if !c.Secure {
		t.Error("Secure is false; the session can travel over plain HTTP")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax — it is the only CSRF defence on the action endpoints", c.SameSite)
	}
}

func TestSafeReturnRefusesOffSiteRedirects(t *testing.T) {
	// An unchecked return parameter turns the sign-in page into a credible
	// phishing launcher: the victim really is on the app's domain when they
	// click.
	for input, want := range map[string]string{
		"":                         "/",
		"/":                        "/",
		"/pulls/2128":              "/pulls/2128",
		"//evil.example.com":       "/",
		"https://evil.example.com": "/",
		"http://evil.example.com":  "/",
		"evil.example.com":         "/",
		"javascript:alert(1)":      "/",
		"\\\\evil.example.com":     "/",
		"/\\evil.example.com":      "/",
		"/%09//evil.example.com":   "/",
		"/pulls/2128?raw=1":        "/pulls/2128?raw=1",
		"/\t//evil.example.com":    "/",
	} {
		if got := safeReturn(input); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRandomStringIsUnique(t *testing.T) {
	seen := make(map[string]bool, 100)
	for range 100 {
		s, err := randomString()
		if err != nil {
			t.Fatalf("randomString: %v", err)
		}
		if seen[s] {
			t.Fatal("randomString repeated a value")
		}
		seen[s] = true
	}
}

func TestOpenRejectsACookieOfAnotherKind(t *testing.T) {
	// The login path hands a state cookie to anyone who asks, before they have
	// proved anything. Both cookies are signed with the same key, so without a
	// kind inside the signed payload the state cookie can simply be renamed to
	// the session cookie: the signature is valid, it has not expired, and its
	// JSON body decodes into an all-empty User. That is a complete
	// authentication bypass with no credential involved.
	m := manager(t)

	state, err := m.seal(kindState, pending{State: "abc", Verifier: "v", Return: "/"}, time.Hour)
	if err != nil {
		t.Fatalf("seal state: %v", err)
	}

	var u User
	if err := m.open(kindSession, state, &u); err == nil {
		t.Fatalf("a state cookie was accepted as a session, producing %+v", u)
	}

	// And the reverse, so a session cookie cannot stand in for the CSRF token.
	sess, err := m.seal(kindSession, User{Subject: "oid-123"}, time.Hour)
	if err != nil {
		t.Fatalf("seal session: %v", err)
	}
	var p pending
	if err := m.open(kindState, sess, &p); err == nil {
		t.Errorf("a session cookie was accepted as state, producing %+v", p)
	}
}

func TestRequireRejectsAStateCookieRenamedToSession(t *testing.T) {
	// The same bypass through the middleware, which is where it would actually
	// be exploited.
	m := manager(t)
	state, err := m.seal(kindState, pending{State: "abc", Verifier: "v", Return: "/"}, time.Hour)
	if err != nil {
		t.Fatalf("seal state: %v", err)
	}

	var reached bool
	h := m.Require(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	req := httptest.NewRequest(http.MethodGet, "/api/pulls", nil)
	req.AddCookie(&http.Cookie{Name: m.SessionCookieName(), Value: state})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if reached || rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, handler reached = %v; want 401 and not reached", rec.Code, reached)
	}
}

func TestNewRefusesTheDevBypassOnARealDeployment(t *testing.T) {
	// The bypass authenticates every request as one user, so a stray
	// development setting on a real deployment would publish the app to anyone
	// who found the URL. A warning in the log is not enough.
	base := Config{Provider: testProvider(t), CookieKey: []byte(key), DevUser: "dev@example.com", Logger: quiet()}

	// Secure cookies mean HTTPS, which means this is not a laptop.
	secure := base
	secure.Secure = true
	if _, err := New(t.Context(), secure); !errors.Is(err, ErrDevBypassSecure) {
		t.Errorf("secure cookies: err = %v, want ErrDevBypassSecure", err)
	}

	// A configured Entra app means somebody intended real authentication.
	for name, mutate := range map[string]func(*Config){
		"tenant": func(c *Config) { c.TenantID = "t" },
		"client": func(c *Config) { c.ClientID = "c" },
		"secret": func(c *Config) { c.ClientSecret = "s" },
		"group":  func(c *Config) { c.AllowedGroupIDs = []string{"g"} },
	} {
		cfg := base
		mutate(&cfg)
		if _, err := New(t.Context(), cfg); !errors.Is(err, ErrDevBypassWithEntra) {
			t.Errorf("%s: err = %v, want ErrDevBypassWithEntra", name, err)
		}
	}

	// The legitimate local case still works.
	if _, err := New(t.Context(), base); err != nil {
		t.Errorf("local development config rejected: %v", err)
	}
}

func TestOpenRejectsStructurallyOddEnvelopes(t *testing.T) {
	// Every one of these is correctly signed, so only the envelope checks
	// stand between them and a decoded value.
	m := manager(t)

	sign := func(body string) string {
		enc := base64.RawURLEncoding.EncodeToString([]byte(body))
		return enc + "." + base64.RawURLEncoding.EncodeToString(m.sign(kindSession, []byte(enc)))
	}
	future := time.Now().Add(time.Hour).Unix()

	for name, body := range map[string]string{
		"no kind":        fmt.Sprintf(`{"exp":%d,"d":{"subject":"x"}}`, future),
		"wrong kind":     fmt.Sprintf(`{"k":"state","exp":%d,"d":{"subject":"x"}}`, future),
		"no expiry":      `{"k":"session","d":{"subject":"x"}}`,
		"expired":        `{"k":"session","exp":1,"d":{"subject":"x"}}`,
		"not an object":  `[]`,
		"data is a list": fmt.Sprintf(`{"k":"session","exp":%d,"d":[]}`, future),
	} {
		var u User
		if err := m.open(kindSession, sign(body), &u); err == nil {
			t.Errorf("%s: accepted, producing %+v", name, u)
		}
	}

	// A null data field decodes to the zero User without error, which is why
	// the kind check has to be what stops a foreign envelope rather than the
	// decode failing.
	var u User
	if err := m.open(kindSession, sign(fmt.Sprintf(`{"k":"session","exp":%d,"d":null}`, future)), &u); err != nil {
		t.Errorf("null data: %v", err)
	}
	if u.Subject != "" {
		t.Errorf("null data produced %+v", u)
	}
}

func TestPresentErrorIsUsedForUnauthenticated(t *testing.T) {
	var saw error
	m := manager(t)
	m.present = func(w http.ResponseWriter, r *http.Request, err error) {
		saw = err
		http.Error(w, "engineering is required to use myapp", http.StatusForbidden)
	}

	rec := httptest.NewRecorder()
	m.Require(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/me", nil))

	if !errors.Is(saw, ErrUnauthenticated) {
		t.Errorf("present got %v, want ErrUnauthenticated", saw)
	}
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "myapp") {
		t.Errorf("consumer wrapper was not what the client saw: %d %q", rec.Code, rec.Body.String())
	}
}

func TestGroupDeniedAdmitsAnyAllowedGroup(t *testing.T) {
	engineers, product := "engineers-oid", "product-oid"
	allow := []string{engineers, product}

	if denied := groupDenied("oid-1", []string{product, "other"}, allow); denied != nil {
		t.Errorf("product member denied: %+v", denied)
	}
	if denied := groupDenied("oid-1", []string{engineers}, allow); denied != nil {
		t.Errorf("engineer denied: %+v", denied)
	}

	denied := groupDenied("oid-1", []string{"other"}, allow)
	if denied == nil {
		t.Fatal("outsider admitted")
	}
	if denied.Subject != "oid-1" || denied.GroupsInToken != 1 || !slices.Equal(denied.GroupIDs, allow) {
		t.Errorf("denied = %+v", *denied)
	}

	overage := groupDenied("oid-1", nil, allow)
	if overage == nil || overage.GroupsInToken != 0 {
		t.Errorf("overage = %+v", overage)
	}
}

func TestInAnyGroup(t *testing.T) {
	u := User{Groups: []string{"engineers-oid"}}
	if !u.InAnyGroup("product-oid", "engineers-oid") {
		t.Error("engineer missed a two-group allowlist")
	}
	if u.InAnyGroup("product-oid") {
		t.Error("engineer passed a product-only check")
	}
	if (User{}).InAnyGroup("engineers-oid") {
		t.Error("empty session passed a group check")
	}
}

func TestRequireAnyGroupRejectsUnauthenticated(t *testing.T) {
	m := manager(t)
	var reached bool
	h := m.RequireAnyGroup("engineers-oid")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/refresh", nil))

	if rec.Code != http.StatusUnauthorized || reached {
		t.Errorf("status = %d, reached = %v; want 401 and not reached", rec.Code, reached)
	}
}

func TestRequireAnyGroupRejectsWrongGroup(t *testing.T) {
	m := manager(t)
	cookie, err := m.seal(kindSession, User{Subject: "oid-1", Groups: []string{"product-oid"}}, time.Hour)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	var reached bool
	h := m.RequireAnyGroup("engineers-oid")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	req := httptest.NewRequest(http.MethodPost, "/api/refresh", nil)
	req.AddCookie(&http.Cookie{Name: m.SessionCookieName(), Value: cookie})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || reached {
		t.Errorf("status = %d, reached = %v; want 403 and not reached", rec.Code, reached)
	}
	if !strings.Contains(rec.Body.String(), ErrGroupDenied.Error()) {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestRequireAnyGroupPassesMatchingGroup(t *testing.T) {
	m := manager(t)
	want := User{Subject: "oid-1", Groups: []string{"product-oid", "engineers-oid"}}
	cookie, err := m.seal(kindSession, want, time.Hour)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	var got User
	var ok bool
	h := m.RequireAnyGroup("engineers-oid")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, ok = UserFrom(r.Context())
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/refresh", nil)
	req.AddCookie(&http.Cookie{Name: m.SessionCookieName(), Value: cookie})
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !ok || !usersEqual(got, want) {
		t.Errorf("user in context = %+v (ok=%v), want %+v", got, ok, want)
	}
}

func TestRequireAnyGroupEmptyListFailsClosed(t *testing.T) {
	m := manager(t)
	cookie, err := m.seal(kindSession, User{Subject: "oid-1", Groups: []string{"engineers-oid"}}, time.Hour)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	var reached bool
	h := m.RequireAnyGroup()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	req := httptest.NewRequest(http.MethodGet, "/api/refresh", nil)
	req.AddCookie(&http.Cookie{Name: m.SessionCookieName(), Value: cookie})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || reached {
		t.Errorf("status = %d, reached = %v; want 403 and not reached", rec.Code, reached)
	}
}

func TestRequireAnyGroupInDevModeSkipsTheCheck(t *testing.T) {
	m := &Manager{
		cfg:      Config{CookieKey: []byte(key), DevUser: "dev@example.com"},
		settings: testSettings(),
		log:      quiet(),
		present:  DefaultPresentError,
	}

	var got User
	h := m.RequireAnyGroup("engineers-oid")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = UserFrom(r.Context())
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/refresh", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !got.Dev {
		t.Error("Dev is false")
	}
}

func TestCookieNamesComeFromSettings(t *testing.T) {
	// The package must not hardcode a consuming app's cookie names, or two
	// apps on the same parent domain would clobber each other's sessions.
	m := manager(t)
	rec := httptest.NewRecorder()
	m.setCookie(rec, m.SessionCookieName(), "v", time.Hour)
	if rec.Result().Cookies()[0].Name != "app_session" {
		t.Errorf("cookie name = %q, want app_session", rec.Result().Cookies()[0].Name)
	}
}

func TestSessionsAreBoundToTheAppIdentity(t *testing.T) {
	// usher is meant to be shared by many apps, and two consumers reusing one
	// CookieKey is an ops shortcut it cannot prevent. The MAC binds the client ID and cookie
	// name, so app A's session presented under app B's cookie name must be
	// rejected even with a shared key — otherwise a user who signed into A
	// reaches B's plain Require routes without ever facing B's allowlist.
	seal := func(m *Manager) string {
		t.Helper()
		cookie, err := m.SealForTest(User{Subject: "oid-123"})
		if err != nil {
			t.Fatalf("SealForTest: %v", err)
		}
		return cookie
	}

	// Distinct cookie names: the documented multi-app shape, one shared Entra
	// registration (so identical, empty client IDs here).
	a := ForTest([]byte(key), Settings{SessionCookie: "app_a_session", StateCookie: "app_a_state"})
	b := ForTest([]byte(key), Settings{SessionCookie: "app_b_session", StateCookie: "app_b_state"})
	var u User
	if err := b.open(kindSession, seal(a), &u); err == nil {
		t.Errorf("app B accepted app A's session, producing %+v", u)
	}

	// Identical cookie names, distinct client IDs: separate registrations.
	c := ForTest([]byte(key), testSettings())
	d := ForTest([]byte(key), testSettings())
	d.cfg.ClientID = "11111111-2222-3333-4444-555555555555"
	if err := d.open(kindSession, seal(c), &u); err == nil {
		t.Errorf("a foreign client ID's session was accepted, producing %+v", u)
	}

	// The sealer itself still round-trips.
	if err := c.open(kindSession, seal(c), &u); err != nil {
		t.Errorf("own session rejected: %v", err)
	}
}

// brokenProvider returns settings without File.Load's validation, as a custom
// Provider implementation could.
type brokenProvider struct{ s Settings }

func (p brokenProvider) Load() (Settings, error) { return p.s, nil }

func TestNewValidatesACustomProvidersSettings(t *testing.T) {
	_, err := New(t.Context(), Config{
		Provider:  brokenProvider{Settings{SessionCookie: "same", StateCookie: "same"}},
		CookieKey: []byte(key),
		DevUser:   "dev@local",
	})
	if err == nil {
		t.Fatal("colliding cookie names from a custom Provider were accepted")
	}
}

func TestLogoutRejectsCrossOriginRequests(t *testing.T) {
	// POST-only stops an <img>, but not an auto-submitting cross-site form;
	// logout reads no cookie, so SameSite does not protect it either.
	m := manager(t)
	for name, headers := range map[string]map[string]string{
		"cross-site fetch":  {"Sec-Fetch-Site": "cross-site"},
		"same-site sibling": {"Sec-Fetch-Site": "same-site"},
		"foreign origin":    {"Origin": "https://evil.example"},
		"opaque origin":     {"Origin": "null"},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			m.handleLogout(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == m.SessionCookieName() {
					t.Error("the session cookie was cleared on a cross-origin request")
				}
			}
		})
	}

	// A browser's own same-origin form keeps working.
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", "http://"+req.Host)
	rec := httptest.NewRecorder()
	m.handleLogout(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("same-origin logout status = %d, want 204", rec.Code)
	}
}
