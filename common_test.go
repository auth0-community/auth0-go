package auth0

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	emptyAudience = []string{}
	emptyIssuer   = ""

	defaultAudience = []string{"audience"}
	defaultIssuer   = "issuer"

	// The default generated token by Chrome jwt extension
	defaultSecret         = []byte("secret")
	defaultSecretProvider = NewKeyProvider(defaultSecret)

	defaultSecretRS256         = genRSASSAJWK(jose.RS256, "")
	defaultSecretProviderRS256 = NewKeyProvider(defaultSecretRS256.Public())

	defaultSecretES384         = genECDSAJWK(jose.ES384, "")
	defaultSecretProviderES384 = NewKeyProvider(defaultSecretES384.Public())
)

func genRSASSAJWK(sigAlg jose.SignatureAlgorithm, kid string) jose.JSONWebKey {
	var bits int
	if sigAlg == jose.RS256 {
		bits = 2048
	}
	if sigAlg == jose.RS512 {
		bits = 4096
	}

	key, _ := rsa.GenerateKey(rand.Reader, bits)

	jsonWebKey := jose.JSONWebKey{
		Key:       key,
		KeyID:     kid,
		Use:       "sig",
		Algorithm: string(sigAlg),
	}

	return jsonWebKey
}

func genECDSAJWK(sigAlg jose.SignatureAlgorithm, kid string) jose.JSONWebKey {
	var c elliptic.Curve
	if sigAlg == jose.ES256 {
		c = elliptic.P256()
	}
	if sigAlg == jose.ES384 {
		c = elliptic.P384()
	}

	key, _ := ecdsa.GenerateKey(c, rand.Reader)

	jsonWebKey := jose.JSONWebKey{
		Key:       key,
		KeyID:     kid,
		Algorithm: string(sigAlg),
	}

	return jsonWebKey
}

func getTestToken(audience []string, issuer string, expTime time.Time, alg jose.SignatureAlgorithm, key interface{}) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}

	cl := jwt.Claims{
		Issuer:   issuer,
		Audience: audience,
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		Expiry:   jwt.NewNumericDate(expTime),
	}

	raw, err := jwt.Signed(signer).Claims(cl).CompactSerialize()
	if err != nil {
		panic(err)
	}
	return raw
}

func getTestTokenWithKid(audience []string, issuer string, expTime time.Time, alg jose.SignatureAlgorithm, key interface{}, kid string) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]interface{}{"kid": kid}}).WithType("JWT"))
	if err != nil {
		panic(err)
	}

	cl := jwt.Claims{
		Issuer:   issuer,
		Audience: audience,
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		Expiry:   jwt.NewNumericDate(expTime),
	}

	raw, err := jwt.Signed(signer).Claims(cl).CompactSerialize()
	if err != nil {
		panic(err)
	}
	return raw
}

func genNewTestServer(genJWKS bool) (JWKClientOptions, string, string, error) {
	// Generate JWKs
	jsonWebKeyRS256 := genRSASSAJWK(jose.RS256, "keyRS256")
	jsonWebKeyES384 := genECDSAJWK(jose.ES384, "keyES384")

	// Generate JWKS
	jwks := JWKS{
		Keys: []jose.JSONWebKey{},
	}
	if genJWKS {
		jwks = JWKS{
			Keys: []jose.JSONWebKey{jsonWebKeyRS256.Public(), jsonWebKeyES384.Public()},
		}
	}
	value, err := json.Marshal(&jwks)

	// Generate Tokens
	tokenRS256 := getTestTokenWithKid(defaultAudience, defaultIssuer, time.Now().Add(24*time.Hour), jose.RS256, jsonWebKeyRS256, "keyRS256")
	tokenES384 := getTestTokenWithKid(defaultAudience, defaultIssuer, time.Now().Add(24*time.Hour), jose.ES384, jsonWebKeyES384, "keyES384")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, string(value))
	}))
	return JWKClientOptions{URI: ts.URL}, tokenRS256, tokenES384, err
}
