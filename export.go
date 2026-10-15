package usher

import (
	"io"
	"log/slog"
)

// ForTest builds a Manager with real (non-development) authentication and no
// Entra provider.
//
// It exists so other packages can exercise the 401 path through the real
// router. [New] would try to reach Entra's discovery endpoint, and a test of
// an API's authentication boundary should not depend on the network.
func ForTest(cookieKey []byte, settings Settings) *Manager {
	settings = settings.withDefaults()
	return &Manager{
		cfg:      Config{CookieKey: cookieKey, TTL: defaultTTL},
		settings: settings,
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		present:  DefaultPresentError,
	}
}

// SealForTest issues a session cookie value for u, so a caller outside this
// package can build an authenticated request.
func (m *Manager) SealForTest(u User) (string, error) {
	return m.seal(kindSession, u, m.cfg.TTL)
}
