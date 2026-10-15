package usher

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestGroupDeniedErrorIsWrapable(t *testing.T) {
	denied := &GroupDeniedError{Subject: "oid-1", GroupIDs: []string{"group-9"}, GroupsInToken: 0}
	wrapped := fmt.Errorf("you are not a member of the group that grants access to myapp: %w", denied)

	if !errors.Is(wrapped, ErrGroupDenied) {
		t.Error("errors.Is(wrapped, ErrGroupDenied) = false")
	}
	var got *GroupDeniedError
	if !errors.As(wrapped, &got) {
		t.Fatal("errors.As failed")
	}
	if got.Subject != "oid-1" || !slices.Equal(got.GroupIDs, []string{"group-9"}) {
		t.Errorf("got %+v", *got)
	}
	if HTTPStatus(wrapped) != http.StatusForbidden {
		t.Errorf("HTTPStatus = %d, want 403", HTTPStatus(wrapped))
	}
}

func TestHTTPStatus(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{ErrUnauthenticated, http.StatusUnauthorized},
		{ErrSignInFailed, http.StatusUnauthorized},
		{ErrSignInExpired, http.StatusBadRequest},
		{ErrInvalidState, http.StatusBadRequest},
		{ErrGroupDenied, http.StatusForbidden},
		{&GroupDeniedError{GroupIDs: []string{"g"}}, http.StatusForbidden},
		{ErrInternal, http.StatusInternalServerError},
		{errors.New("mystery"), http.StatusInternalServerError},
	} {
		if got := HTTPStatus(tc.err); got != tc.want {
			t.Errorf("HTTPStatus(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}

func TestDefaultPresentError(t *testing.T) {
	rec := httptest.NewRecorder()
	DefaultPresentError(rec, httptest.NewRequest(http.MethodGet, "/", nil), ErrUnauthenticated)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unauthenticated") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestEntraErrorCode(t *testing.T) {
	for _, tc := range []struct {
		name        string
		description string
		want        string
	}{
		{name: "empty", description: "", want: ""},
		{name: "no code", description: "something went wrong", want: ""},
		{name: "consent declined", description: "AADSTS65004: User declined to consent to access the app.", want: "AADSTS65004"},
		{name: "admin consent required", description: "AADSTS90095: Admin consent is required for the permissions requested by this application.", want: "AADSTS90095"},
		{name: "external account names a third party", description: "AADSTS50020: User account 'someone@outlook.com' from identity provider 'live.com' does not exist in tenant 'Contoso'.", want: "AADSTS50020"},
		{name: "blocked user names a upn", description: "AADSTS50105: The signed in user 'someone@contoso.com' is blocked because they are not a direct member of a group with access.", want: "AADSTS50105"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := entraErrorCode(tc.description)
			if got != tc.want {
				t.Fatalf("entraErrorCode(%q) = %q, want %q", tc.description, got, tc.want)
			}
			if strings.Contains(got, "@") {
				t.Fatalf("entraErrorCode(%q) = %q, which carries an address", tc.description, got)
			}
		})
	}
}

func TestMissingFieldError(t *testing.T) {
	err := &MissingFieldError{Field: "tenant ID"}
	if !strings.Contains(err.Error(), "tenant ID") {
		t.Errorf("Error = %q", err.Error())
	}
}
