package usher

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
)

// Startup and configuration errors. These are returned from [New], not from
// HTTP handlers. Consumers wrap them to name env vars or files.
var (
	ErrProviderRequired   = errors.New("usher: config provider is required")
	ErrCookieKeyTooShort  = errors.New("usher: cookie key must be at least 32 bytes")
	ErrDevBypassSecure    = errors.New("usher: development bypass cannot run with secure cookies")
	ErrDevBypassWithEntra = errors.New("usher: development bypass and Entra settings are both configured")
	ErrGroupDenied        = errors.New("required group absent from token")
	ErrUnauthenticated    = errors.New("unauthenticated")
	ErrSignInFailed       = errors.New("sign-in failed")
	ErrSignInExpired      = errors.New("sign-in expired, try again")
	ErrInvalidState       = errors.New("sign-in failed")
	ErrInternal           = errors.New("internal error")
	ErrMalformedCookie    = errors.New("usher: malformed cookie")
	ErrBadSignature       = errors.New("usher: bad signature")
	ErrWrongCookieKind    = errors.New("usher: wrong cookie kind")
	ErrExpiredCookie      = errors.New("usher: expired")
)

// MissingFieldError is returned when a required settings or Entra field is empty.
type MissingFieldError struct {
	Field string
}

func (e *MissingFieldError) Error() string {
	return fmt.Sprintf("usher: %s is required", e.Field)
}

// GroupDeniedError is returned when the ID token or session does not contain
// any of the required groups. Its Error text is deliberately generic:
// consumers should wrap it into copy that names the app, for example
//
//	"you are not a member of the group that grants access to myapp"
//
// Subject is the Entra object ID, not an email. GroupIDs is the allowlist
// that was checked, not the groups the person actually has. GroupsInToken
// is 0 when the claim was missing entirely, which is the overage symptom.
type GroupDeniedError struct {
	Subject       string
	GroupIDs      []string
	GroupsInToken int
}

func (e *GroupDeniedError) Error() string { return ErrGroupDenied.Error() }
func (e *GroupDeniedError) Unwrap() error { return ErrGroupDenied }
func (e *GroupDeniedError) HTTPStatus() int {
	return http.StatusForbidden
}

// HTTPStatus returns the status a handler should use for err. Unknown errors
// are 500.
func HTTPStatus(err error) int {
	var hs interface{ HTTPStatus() int }
	if errors.As(err, &hs) {
		return hs.HTTPStatus()
	}
	switch {
	case errors.Is(err, ErrUnauthenticated), errors.Is(err, ErrSignInFailed):
		return http.StatusUnauthorized
	case errors.Is(err, ErrInvalidState), errors.Is(err, ErrSignInExpired):
		return http.StatusBadRequest
	case errors.Is(err, ErrGroupDenied):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// DefaultPresentError writes err's own message and [HTTPStatus]. It never
// names a consuming app.
func DefaultPresentError(w http.ResponseWriter, _ *http.Request, err error) {
	http.Error(w, err.Error(), HTTPStatus(err))
}

// aadstsCode matches the AADSTS<digits> token Entra puts at the front of an
// error_description.
var aadstsCode = regexp.MustCompile(`AADSTS[0-9]+`)

// entraErrorCode pulls the AADSTS code out of an Entra error_description and
// discards the rest.
//
// The rest is unbounded free text that can name someone. AADSTS50020, 90072
// and 50105 all interpolate a user's email or UPN into the description, and
// the first two fire precisely for accounts that are not in the tenant — so
// this is not the user identity already logged on authenticated calls.
func entraErrorCode(description string) string {
	return aadstsCode.FindString(description)
}
