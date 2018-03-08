package auth0

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestFromRequestHeaderExtraction(t *testing.T) {
	referenceToken := getTestToken(defaultAudience, defaultIssuer, time.Now(), jose.HS256, defaultSecret)

	headerTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	headerValue := fmt.Sprintf("Bearer %s", referenceToken)
	headerTokenRequest.Header.Add("Authorization", headerValue)

	token, err := FromHeader(headerTokenRequest)
	if err != nil {
		t.Error(err)
		return
	}

	claims := jwt.Claims{}
	err = token.Claims([]byte("secret"), &claims)
	if err != nil {
		t.Errorf("Claims should be decoded correctly with default token: %q \n", err)
		t.FailNow()
	}

	if claims.Issuer != defaultIssuer || !reflect.DeepEqual(claims.Audience, jwt.Audience(defaultAudience)) {
		t.Error("Invalid issuer, audience or subject:", claims.Issuer, claims.Audience)
	}
}

func TestFromRequestParamsExtraction(t *testing.T) {
	referenceToken := getTestToken(defaultAudience, defaultIssuer, time.Now(), jose.HS256, defaultSecret)

	paramTokenRequest, _ := http.NewRequest("", "http://localhost?token="+referenceToken, nil)

	token, err := FromParams(paramTokenRequest)
	if err != nil {
		t.Error(err)
		return
	}

	claims := jwt.Claims{}
	err = token.Claims([]byte("secret"), &claims)
	if err != nil {
		t.Errorf("Claims should be decoded correctly with default token: %q \n", err)
		t.FailNow()
	}

	if claims.Issuer != defaultIssuer || !reflect.DeepEqual(claims.Audience, jwt.Audience(defaultAudience)) {
		t.Error("Invalid issuer, audience or subject:", claims.Issuer, claims.Audience)
	}
}

func TestFromMultipleExtraction(t *testing.T) {
	extractor := FromMultiple(RequestTokenExtractorFunc(FromHeader), RequestTokenExtractorFunc(FromParams))

	referenceToken := getTestToken(defaultAudience, defaultIssuer, time.Now(), jose.HS256, defaultSecret)
	headerTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	headerValue := fmt.Sprintf("Bearer %s", referenceToken)
	headerTokenRequest.Header.Add("Authorization", headerValue)
	paramTokenRequest, _ := http.NewRequest("", "http://localhost?token="+referenceToken, nil)
	brokenParamTokenRequest, _ := http.NewRequest("", "http://localhost?token=broken", nil)

	for _, r := range []*http.Request{headerTokenRequest, paramTokenRequest, brokenParamTokenRequest} {
		token, err := extractor.Extract(r)
		if err != nil {
			if r == brokenParamTokenRequest && err.Error() == "square/go-jose: compact JWS format must have three parts" {
				// Checking that the JWT error is returned.
				continue
			}
			t.Error(err)
			return
		}

		claims := jwt.Claims{}
		err = token.Claims([]byte("secret"), &claims)
		if err != nil {
			t.Errorf("Claims should be decoded correctly with default token: %q \n", err)
			t.FailNow()
		}

		if claims.Issuer != defaultIssuer || !reflect.DeepEqual(claims.Audience, jwt.Audience(defaultAudience)) {
			t.Error("Invalid issuer, audience or subject:", claims.Issuer, claims.Audience)
		}
	}
}

func TestInvalidExtract(t *testing.T) {
	headerTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	_, err := FromHeader(headerTokenRequest)

	if err == nil {
		t.Error("A request without valid Authorization header should return an error.")
	}
}
