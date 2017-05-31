package auth0

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

var (
	jwks = `{"keys":[{"alg":"RS256","kty":"RSA","use":"sig","x5c":["MIIC8jCCAdqgAwIBAgIJZvOZ2bLIbtRwMA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNVBAMTFXZpdGFjdGl2LmV1LmF1dGgwLmNvbTAeFw0xNjA4MjIxMTEyNDdaFw0zMDA1MDExMTEyNDdaMCAxHjAcBgNVBAMTFXZpdGFjdGl2LmV1LmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALSn7IjSFthxlvCyIwxWOMrtgnbwI9CT1HXjv1CYHNUqdsjPZaQ88llL42EiKmTR2KGhqG70h0mTteCQmzPRJpQBAy+WbZzRAXmQSThvmSkYUd98Lp9VC7gpLEl3lcUQoMUAebXvcPW8/gy9FkYJGrgS4+mGm5gTnE5PpbjGcrI3KJayTtPvtDSMkhPsCL8FioZMurlQ5oTBBTOUXyAMspV4VOwpkCsj4eoM7qujejR2WJz9X23vTk9KukGztGq6xd2SFOtJbI44DP0Q5QvW+0jEFUqxW+ehibVCABm8NmxQZZZwm1bCytRI8HL+JAEx0Dy4IeAm/SNesdMFU5Wj6MkCAwEAAaMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU6LvxiksMqaMG08CP7QCXY6wkGDQwDQYJKoZIhvcNAQEFBQADggEBAEEfpNPgAEfFY+u8QLiEFqGisR2zpO89JxEo7E4BKMlLF111X2fik9BgbpWQuNDDbCYFducmd33hVHvtWyc8Wx5Qf+ShhUSWPT0Xhcs1FX+VHqWHCAWLTHK8Upq/MuZTi23p+0Naou5HkO3yCnaBabbLQROrS72gpoVhGZOu7FlHzRmt+Xab1+e68hVgMY295Zt0gjrHOFLOFMwyBH2u9TGNmcVGttVSjmXUMUkNCwK+3GV72ESKafaZ5dDVwBzpkRm0F2knyuTXCayKynTugMiBbWdWrX1yRV4c1sgBWT49Dy0tpVpg+jLxNcXPZQRQfQ1MU+fKp0Eu51DHtaYXPeQ="],"n":"tKfsiNIW2HGW8LIjDFY4yu2CdvAj0JPUdeO_UJgc1Sp2yM9lpDzyWUvjYSIqZNHYoaGobvSHSZO14JCbM9EmlAEDL5ZtnNEBeZBJOG-ZKRhR33wun1ULuCksSXeVxRCgxQB5te9w9bz-DL0WRgkauBLj6YabmBOcTk-luMZysjcolrJO0--0NIySE-wIvwWKhky6uVDmhMEFM5RfIAyylXhU7CmQKyPh6gzuq6N6NHZYnP1fbe9OT0q6QbO0arrF3ZIU60lsjjgM_RDlC9b7SMQVSrFb56GJtUIAGbw2bFBllnCbVsLK1Ejwcv4kATHQPLgh4Cb9I16x0wVTlaPoyQ","e":"AQAB","kid":"NzIwQTBBNDhFRjgwMUZENkU0Q0E3RTdBODBDMkI5Qzg3Q0JGMTNGRQ","x5t":"NzIwQTBBNDhFRjgwMUZENkU0Q0E3RTdBODBDMkI5Qzg3Q0JGMTNGRQ"}]}`
)

func TestJWKDownloadKey(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, jwks)
	}))
	opts := JWKClientOptions{URI: ts.URL}
	client := NewJWKClient(opts)

	err := client.downloadKeys()
	if err != nil {
		t.Errorf("The keys should have been correctly received: %q", err)
	}
}
