package auth0

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/go-errors/errors"
	"gopkg.in/square/go-jose.v2"
)

var (
	ErrInvalidContentType = errors.New("should have a JSON content type for JWKS endpoint")
	ErrInvalidAlgorithm   = errors.New("algorithm is invalid")
)

type JWKClientOptions struct {
	URI string
}

type JWKS struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

type JWKClient struct {
	keyCacher KeyCacher
	mu        sync.Mutex
	options   JWKClientOptions
	extractor RequestTokenExtractor
}

// NewJWKClient creates a new JWKClient instance from the
// provided options.
func NewJWKClient(options JWKClientOptions, extractor RequestTokenExtractor) *JWKClient {
	if extractor == nil {
		extractor = RequestTokenExtractorFunc(FromHeader)
	}

	keyCacher := newMemoryPersistentKeyCacher()

	return &JWKClient{
		keyCacher,
		sync.Mutex{},
		options,
		extractor,
	}
}

func NewJWKClientWithCustomCacher(options JWKClientOptions, extractor RequestTokenExtractor, keyCacher KeyCacher) *JWKClient {
	if extractor == nil {
		extractor = RequestTokenExtractorFunc(FromHeader)
	}
	if keyCacher == nil {
		keyCacher = newMemoryPersistentKeyCacher()
	}

	return &JWKClient{
		keyCacher,
		sync.Mutex{},
		options,
		extractor,
	}
}

// GetKey returns the key associated with the provided ID.
func (j *JWKClient) GetKey(ID string) (jose.JSONWebKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	searchedKey, err := j.keyCacher.Get(ID)

	if searchedKey == nil {
		if keys, err := j.downloadKeys(); err != nil {
			return jose.JSONWebKey{}, err
		} else {
			addedKey, err := j.keyCacher.Add(ID, keys)
			if addedKey == nil {
				return jose.JSONWebKey{}, err
			}
			return *addedKey, err
		}
	}
	return *searchedKey, err
}

func (j *JWKClient) downloadKeys() ([]jose.JSONWebKey, error) {
	resp, err := http.Get(j.options.URI)

	if err != nil {
		return []jose.JSONWebKey{}, err
	}
	defer resp.Body.Close()

	if contentH := resp.Header.Get("Content-Type"); !strings.HasPrefix(contentH, "application/json") {
		return []jose.JSONWebKey{}, ErrInvalidContentType
	}

	var jwks = JWKS{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return []jose.JSONWebKey{}, err
	}

	if len(jwks.Keys) < 1 {
		return []jose.JSONWebKey{}, ErrNoKeyFound
	}

	return jwks.Keys, nil
}

// GetSecret implements the GetSecret method of the SecretProvider interface.
func (j *JWKClient) GetSecret(r *http.Request) (interface{}, error) {
	token, err := j.extractor.Extract(r)
	if err != nil {
		return nil, err
	}

	if len(token.Headers) < 1 {
		return nil, ErrNoJWTHeaders
	}

	header := token.Headers[0]

	return j.GetKey(header.KeyID)
}
