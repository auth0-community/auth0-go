package auth0

import (
	"errors"
	"net/http"
	"strings"

	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	ErrTokenNotFound = errors.New("Token not found")
)

// RequestTokenExtractor can extract a JWT
// from a request.
type RequestTokenExtractor interface {
	Extract(r *http.Request) (*jwt.JSONWebToken, error)
}

// RequestTokenExtractorFunc function conforming
// to the RequestTokenExtractor interface.
type RequestTokenExtractorFunc func(r *http.Request) (*jwt.JSONWebToken, error)

// Extract calls f(r)
func (f RequestTokenExtractorFunc) Extract(r *http.Request) (*jwt.JSONWebToken, error) {
	return f(r)
}

// FromMultiple combines multiple extractors by chaining.
func FromMultiple(extractors ...RequestTokenExtractor) RequestTokenExtractor {
	return RequestTokenExtractorFunc(func(r *http.Request) (*jwt.JSONWebToken, error) {
		for _, e := range extractors {
			if token, err := e.Extract(r); err == nil {
				return token, nil
			}
		}
		return nil, ErrTokenNotFound
	})
}

// FromHeader looks for the request in the
// authentication header or call ParseMultipartForm
// if not present.
// TODO: Implement parsing form data.
func FromHeader(r *http.Request) (*jwt.JSONWebToken, error) {
	raw, err := fromHeader(r)
	if err != nil {
		return nil, err
	}
	return jwt.ParseSigned(string(raw))
}

func fromHeader(r *http.Request) ([]byte, error) {
	if authorizationHeader := r.Header.Get("Authorization"); len(authorizationHeader) > 7 && strings.EqualFold(authorizationHeader[0:7], "BEARER ") {
		return []byte(authorizationHeader[7:]), nil
	}
	return nil, ErrTokenNotFound
}

// FromParams returns the JWT when passed as the URL query param "token".
func FromParams(r *http.Request) (*jwt.JSONWebToken, error) {
	raw, err := fromParams(r)
	if err != nil {
		return nil, err
	}
	return jwt.ParseSigned(string(raw))
}

func fromParams(r *http.Request) ([]byte, error) {
	if token := r.URL.Query().Get("token"); token != "" {
		return []byte(token), nil
	}
	return nil, ErrTokenNotFound
}
