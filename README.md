# usher

Microsoft Entra ID sign-in for Go browser apps: authorization code + PKCE, a signed session cookie, a login group allowlist, and an optional per-route group check.

This is an ordinary OIDC relying party. It is not an OAuth authorization server or bridge, and it does not implement Dynamic Client Registration; a browser app does not need either.

## Use

App-specific identity (cookie names, route paths) comes from a JSON file. Secrets stay in the process environment.

```json
{
  "sessionCookie": "myapp_session",
  "stateCookie": "myapp_oidc_state",
  "loginPath": "/auth/login",
  "callbackPath": "/auth/callback",
  "logoutPath": "/auth/logout"
}
```

```go
m, err := usher.New(ctx, usher.Config{
    Provider:        usher.File{Path: "config/usher.json"},
    TenantID:        os.Getenv("ENTRA_TENANT_ID"),
    ClientID:        os.Getenv("ENTRA_CLIENT_ID"),
    ClientSecret:    os.Getenv("ENTRA_CLIENT_SECRET"),
    RedirectURL:     os.Getenv("ENTRA_REDIRECT_URL"),
    AllowedGroupIDs: strings.Split(os.Getenv("ENTRA_ALLOWED_GROUP_IDS"), ","),
    CookieKey:       []byte(os.Getenv("SESSION_KEY")),
    Secure:          true,
    PresentError:    presentAuthError,
})
```

`PresentError` is how the consumer names the app. usher's own messages never do:

```go
func presentAuthError(w http.ResponseWriter, r *http.Request, err error) {
    var denied *usher.GroupDeniedError
    if errors.As(err, &denied) {
        http.Error(w, "you are not a member of the group that grants access to myapp", http.StatusForbidden)
        return
    }
    usher.DefaultPresentError(w, r, err)
}
```

Register routes and wrap the API:

```go
m.Routes(mux)          // login, callback, logout
mux.Route("/api", func(r chi.Router) {
    r.Use(m.Require) // any signed-in user; login already applied the app allowlist
    r.Get("/items", list)
    r.With(m.RequireAnyGroup(engineersOID)).Post("/items", mutate)
})
```

Several apps can share one Entra registration, but a registration cannot filter by redirect URI. Assign it the union of groups those apps need, and put each app's login allowlist in `AllowedGroupIDs`. Token groups ride on `User` so route checks do not re-parse the ID token.

The app registration must emit **Groups assigned to the application**, not All groups. All groups trips Entra overage above ~200 memberships and the `groups` claim disappears.

## Revocation

Sessions are stateless: the cookie is the session, group membership is baked in at sign-in, and nothing re-checks Entra until the cookie expires (default TTL 12 hours). Removing someone from a group — or from the tenant — does not end a session they already hold.

Two levers exist, and every consuming app should know which one it would pull:

- **Rotate the cookie key.** A new `CookieKey` invalidates every outstanding session at once. This is the emergency lever for an offboarding or a suspected cookie theft; the cost is that everyone signs in again.
- **Shorten the TTL.** `Config.TTL` bounds how long a stale session can outlive a group change. Apps whose sessions authorize writes with real-world effect should consider something shorter than the default.

## Install

```
go get github.com/sodahealth-oss/usher
```
