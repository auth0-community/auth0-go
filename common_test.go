package auth0

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	// The default generated token by Chrome jwt extension
	defaultSecret         = []byte("secret")
	defaultAudience       = []string{"audience"}
	defaultIssuer         = "issuer"
	defaultSecretProvider = NewKeyProvider(defaultSecret)
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
