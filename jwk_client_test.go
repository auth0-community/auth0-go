package auth0

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
)

type mockKeyCacher struct {
	get   bool
	add   bool
	key   jose.JSONWebKey
	keyID string
}

func newMockKeyCacher(get bool, add bool, key jose.JSONWebKey, keyID string) *mockKeyCacher {
	return &mockKeyCacher{
		get,
		add,
		key,
		keyID,
	}
}

func (mockKC *mockKeyCacher) Get(keyID string) (jose.JSONWebKey, bool) {
	if mockKC.get {
		mockKey := jose.JSONWebKey{Use: "test"}
		mockKey.KeyID = mockKC.keyID
		return mockKey, true
	}

	return jose.JSONWebKey{}, false
}

func (mockKC *mockKeyCacher) Add(keyID string, webKeys []jose.JSONWebKey) (jose.JSONWebKey, bool) {
	if mockKC.add {
		mockKey := jose.JSONWebKey{Use: "test"}
		mockKey.KeyID = mockKC.keyID
		return mockKey, true
	}
	return jose.JSONWebKey{}, false
}

func TestJWKDownloadKeySuccess(t *testing.T) {
	// Generate JWKs
	jsonWebKeyRS256 := genRSASSAJWK(jose.RS256, "keyRS256")
	jsonWebKeyES384 := genECDSAJWK(jose.ES384, "keyES384")

	// Generate JWKS
	jwks := JWKS{
		Keys: []jose.JSONWebKey{jsonWebKeyRS256.Public(), jsonWebKeyES384.Public()},
	}
	value, err := json.Marshal(&jwks)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// Generate Tokens
	tokenRS256 := getTestTokenWithKid(defaultAudience, defaultIssuer, time.Now().Add(24*time.Hour), jose.RS256, jsonWebKeyRS256, "keyRS256")
	tokenES384 := getTestTokenWithKid(defaultAudience, defaultIssuer, time.Now().Add(24*time.Hour), jose.ES384, jsonWebKeyES384, "keyES384")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, string(value))
	}))
	opts := JWKClientOptions{URI: ts.URL}
	client := NewJWKClient(opts, nil)

	keys, err := client.downloadKeys()
	if err != nil || len(keys) < 1 {
		t.Errorf("The keys should have been correctly received: %v", err)
		t.FailNow()
	}

	for _, token := range []string{tokenRS256, tokenES384} {
		req, _ := http.NewRequest("", "http://localhost", nil)
		headerValue := fmt.Sprintf("Bearer %s", token)
		req.Header.Add("Authorization", headerValue)

		_, err = client.GetSecret(req)
		if err != nil {
			t.Errorf("Should be considered as valid, but failed with error: " + err.Error())
		}
	}
}

func TestJWKDownloadKeyNoKeys(t *testing.T) {
	// Generate JWKs
	jsonWebKeyES384 := genECDSAJWK(jose.ES384, "keyES384")

	// Generate JWKS
	jwks := JWKS{
		Keys: []jose.JSONWebKey{},
	}
	value, err := json.Marshal(&jwks)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// Generate Tokens
	tokenES384 := getTestTokenWithKid(defaultAudience, defaultIssuer, time.Now().Add(24*time.Hour), jose.ES384, jsonWebKeyES384, "keyES384")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, string(value))
	}))
	opts := JWKClientOptions{URI: ts.URL}
	client := NewJWKClient(opts, nil)

	req, _ := http.NewRequest("", "http://localhost", nil)
	headerValue := fmt.Sprintf("Bearer %s", tokenES384)
	req.Header.Add("Authorization", headerValue)

	_, err = client.GetSecret(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No Keys has been found")
}

func TestJWKDownloadKeyNotFound(t *testing.T) {
	// Generate JWKs
	jsonWebKeyRS256 := genRSASSAJWK(jose.RS256, "keyRS256")
	jsonWebKeyES384 := genECDSAJWK(jose.ES384, "keyES384")

	// Generate JWKS
	jwks := JWKS{
		Keys: []jose.JSONWebKey{jsonWebKeyRS256.Public()},
	}
	value, err := json.Marshal(&jwks)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// Generate Tokens
	tokenES384 := getTestTokenWithKid(defaultAudience, defaultIssuer, time.Now().Add(24*time.Hour), jose.ES384, jsonWebKeyES384, "keyES384")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, string(value))
	}))
	opts := JWKClientOptions{URI: ts.URL}
	client := NewJWKClient(opts, nil)

	req, _ := http.NewRequest("", "http://localhost", nil)
	headerValue := fmt.Sprintf("Bearer %s", tokenES384)
	req.Header.Add("Authorization", headerValue)

	_, err = client.GetSecret(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No Keys has been found")
}

func TestJWKDownloadKeyInvalid(t *testing.T) {

	// Invalid content
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Invalid Data")
	}))

	opts := JWKClientOptions{URI: ts.URL}
	client := NewJWKClient(opts, nil)

	_, err := client.downloadKeys()
	if err != ErrInvalidContentType {
		t.Errorf("An ErrInvalidContentType should be returned in case of invalid Content-Type Header.")
	}

	// Invalid Payload
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, "Invalid Data")
	}))

	opts = JWKClientOptions{URI: ts.URL}
	client = NewJWKClient(opts, nil)

	_, err = client.downloadKeys()
	if err == nil {
		t.Errorf("An non JSON payload should return an error.")
	}
}

func TestJWKWithCacherGettingKey(t *testing.T) {

	opts := JWKClientOptions{URI: "localhost"}
	kc := newMockKeyCacher(true, false, jose.JSONWebKey{}, "key1")
	client := NewJWKClientWithCustomCacher(opts, nil, kc)

	searchedKey, exist := client.GetKey(kc.keyID)
	assert.NotEmpty(t, searchedKey)
	assert.Nil(t, exist)
}

func TestJWKWithNilCacherGettingKey(t *testing.T) {

	opts := JWKClientOptions{URI: "localhost"}
	client := NewJWKClientWithCustomCacher(opts, nil, nil)

	searchedKey, exist := client.GetKey("test_key")
	assert.Empty(t, searchedKey)
	assert.Error(t, exist)
}

func TestJWKWithCacherAddingDownloadedKey(t *testing.T) {

	// Generate JWKs
	jsonWebKeyRS256 := genRSASSAJWK(jose.RS256, "keyRS256")
	jsonWebKeyES384 := genECDSAJWK(jose.ES384, "keyES384")

	// Generate JWKS
	jwks := JWKS{
		Keys: []jose.JSONWebKey{jsonWebKeyRS256.Public(), jsonWebKeyES384.Public()},
	}
	value, err := json.Marshal(&jwks)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, string(value))
	}))

	opts := JWKClientOptions{URI: ts.URL}
	kc := newMockKeyCacher(false, true, jose.JSONWebKey{}, "add")
	client := NewJWKClientWithCustomCacher(opts, nil, kc)

	keys, err := client.downloadKeys()
	if err != nil || len(keys) < 1 {
		t.Errorf("The keys should have been correctly received: %v", err)
		t.FailNow()
	}

	searchedKey, err := client.GetKey(kc.keyID)
	assert.Equal(t, kc.keyID, searchedKey.KeyID)
	assert.NotEmpty(t, searchedKey)
	assert.Nil(t, err)
}

func TestJWKWithCacherAddingInvalidDownloadedKey(t *testing.T) {

	// Generate JWKs
	jsonWebKeyRS256 := genRSASSAJWK(jose.RS256, "keyRS256")
	jsonWebKeyES384 := genECDSAJWK(jose.ES384, "keyES384")

	// Generate JWKS
	jwks := JWKS{
		Keys: []jose.JSONWebKey{jsonWebKeyRS256.Public(), jsonWebKeyES384.Public()},
	}
	value, err := json.Marshal(&jwks)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, string(value))
	}))

	opts := JWKClientOptions{URI: ts.URL}
	kc := newMockKeyCacher(false, false, jose.JSONWebKey{}, "add")
	client := NewJWKClientWithCustomCacher(opts, nil, kc)

	keys, err := client.downloadKeys()
	if err != nil || len(keys) < 1 {
		t.Errorf("The keys should have been correctly received: %v", err)
		t.FailNow()
	}

	searchedKey, err := client.GetKey(kc.keyID)
	assert.Empty(t, searchedKey.KeyID)
	assert.Empty(t, searchedKey)
	assert.Error(t, err)
}
