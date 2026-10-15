// Package usher authenticates users against Microsoft Entra ID and carries
// the result in a signed cookie.
//
// It is an ordinary OIDC relying party: authorization code with PKCE, straight
// to Entra. That is the right shape for a browser app. MCP clients are a
// different problem — they require RFC 7591 Dynamic Client Registration, which
// Entra does not implement, so they need an OAuth authorization server in
// front of Entra. A browser app does not, and this package does not try to be
// one.
//
// The hardening a hand-rolled JWT validator would have to provide — JWKS
// caching and refresh, a signing-algorithm allowlist, issuer and audience
// checks — comes from go-oidc, which is purpose-built for the relying-party
// side.
//
// # Sessions are stateless
//
// The session is an HMAC-signed cookie rather than a server-side row. An app
// that scales to zero, sleeps and resumes, or runs several replicas keeps its
// sessions without any coordination. Signing out clears the cookie; there is
// no server-side revocation, which is acceptable for internal tools with
// short-lived sessions.
//
// # App-specific identity lives in a config provider
//
// Cookie names, route paths, and anything else that must differ between
// consuming apps is loaded through [Provider]. The only implementation in this
// module is [File], a JSON file. Secrets and environment-dependent flags
// (cookie signing key, client secret, Secure) stay on [Config] and are
// supplied by the process, typically from the environment.
//
// # Groups are identity, not a policy engine
//
// A shared Entra app registration is assigned the union of every consumer's
// groups. Login therefore takes an allowlist ([Config.AllowedGroupIDs]): any
// one membership mints a session. The groups from the token ride on [User]
// so the consuming app can narrow further with [Manager.RequireAnyGroup]
// (product may read, engineers may write). Per-route mapping of group to
// action stays in the app; this package does not grow roles or a PDP.
//
// # Errors are wrapable, not branded
//
// Handlers in this package never name the consuming app. Failures are the
// exported error values in this file; consumers inspect them with errors.Is /
// errors.As and wrap them into copy such as "engineering is required to use
// myapp". Set [Config.PresentError] to do that on the HTTP path, or leave it
// nil to serve the generic messages.
package usher
