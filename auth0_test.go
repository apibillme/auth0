package auth0

import (
	"errors"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	jwxt "github.com/lestrrat-go/jwx/jwt"

	"github.com/spf13/cast"

	"github.com/apibillme/stubby"
	"github.com/gbrlsnchs/jwt"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/tidwall/buntdb"
	"github.com/valyala/fasthttp"
)

func TestSpec(t *testing.T) {

	jwks := `{"keys":[{"alg":"RS256","kty":"RSA","use":"sig","x5c":["MIIDATCCAemgAwIBAgIJPymo9uL6RAIZMA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMTE2FwaWJpbGxtZS5hdXRoMC5jb20wHhcNMTgwODExMTU1MzQ3WhcNMzIwNDE5MTU1MzQ3WjAeMRwwGgYDVQQDExNhcGliaWxsbWUuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3YWnALuhgE6pQZa8WLJZkCaBmhzgwg4jyqHlf50B6Sed3tBatFkZ3zTXt1Ic/9axylVyOyB4Bzcnsa82oLlqiLrQ5QRpgcSzcCPhDp3ZrOhimB8bSC6c01ZDMsCRxdnFGJjSk0yDIVf3MSk8UbAPtqyf71z6rwLOrGh9JF6K9ZpMiBWuKhLXGaVHYV5AfVGhEidWYXpnTezpypzWxBFc9F/sIR6sK5NerBSIRcCdEpPoPV7eOLp1SFhP9TPhiCeVJCi4mnjWGQeOl8eYK25dLad8iqxLKmIigsqs14pp/+oT08gBLF5ga6UlB76dFWUwIqIWzjGuQ2LI+G5gkUi/hQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSPDPNbqT4Jgh9VAEyhDoiiOXECTDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAGRn08+g+JPZye1yxqgmxB4SDXktn32qb3ZY238E+Km/cvX2H27oWc53Hj+VKyrGuZjniIcVRfuWMJOpQkEltfyAPR9Q1/B7vbJa7/+YWAyeO1vd6XtFnwDrRaOKZAo4CCVYSlVCSrSho/Q+nPLCOVRSXHlGxWQr9ZuqpMF8RVPNDe9bPLWQM8ceYfJq8dCFEM1QRPXM7WXwfgrht+G48JqeOrZZcTsM6GlRijzp7av4u0D0GWh6kUI/iilNIQBFifwALPI1HZQihFFUUNEVH246Im17MzBVMxWauii+fSnE/5FA7qtNkA/tlMCavIVJ76tuSydD5ww+L/hEV7v2A8I="],"n":"3YWnALuhgE6pQZa8WLJZkCaBmhzgwg4jyqHlf50B6Sed3tBatFkZ3zTXt1Ic_9axylVyOyB4Bzcnsa82oLlqiLrQ5QRpgcSzcCPhDp3ZrOhimB8bSC6c01ZDMsCRxdnFGJjSk0yDIVf3MSk8UbAPtqyf71z6rwLOrGh9JF6K9ZpMiBWuKhLXGaVHYV5AfVGhEidWYXpnTezpypzWxBFc9F_sIR6sK5NerBSIRcCdEpPoPV7eOLp1SFhP9TPhiCeVJCi4mnjWGQeOl8eYK25dLad8iqxLKmIigsqs14pp_-oT08gBLF5ga6UlB76dFWUwIqIWzjGuQ2LI-G5gkUi_hQ","e":"AQAB","kid":"RTAxQzU0MjA0NUM2NzBBQThENzA3RDBDOEVFNDY0NUEyNjc3QkJBQw","x5t":"RTAxQzU0MjA0NUM2NzBBQThENzA3RDBDOEVFNDY0NUEyNjc3QkJBQw"}]}`

	Convey("Integration Tests", t, func() {
		db, err := buntdb.Open(":memory:")
		if err != nil {
			log.Panic(err)
		}
		defer db.Close()

		Convey("Success - fresh key on first request - fasthttp", func() {
			// set vars
			jwkEndpoint := "https://example.com/"
			audience := "https://httpbin.org/"

			// Timestamp the beginning.
			now := time.Now()
			// Define a signer.
			hs256 := jwt.NewHS256("secret")
			jot := &jwt.JWT{
				Issuer:         "https://example.auth0.com/",
				Subject:        "user@email.com",
				Audience:       audience,
				ExpirationTime: now.Add(24 * 30 * 12 * time.Hour).Unix(),
				NotBefore:      now.Add(time.Duration(-10) * time.Minute).Unix(),
				IssuedAt:       now.Unix(),
			}
			jot.SetAlgorithm(hs256)
			jot.SetKeyID("QkZBNjE4MzI3MTQwMEZCNDg0RjIyMDgyMDBFMTZFRUIwOEE5NTAxNg")

			payload, err := jwt.Marshal(jot)
			So(err, ShouldBeNil)

			tokenBytes, err := hs256.Sign(payload)
			So(err, ShouldBeNil)
			jwtToken := cast.ToString(tokenBytes)

			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.Add("Authorization", "Bearer "+jwtToken)

			token, err := verifyToken(jwtToken)
			So(err, ShouldBeNil)

			// stub out needed functions with success factors
			set, err := jwk.ParseString(jwks)
			So(err, ShouldBeNil)
			stub1 := stubby.StubFunc(&jwkFetch, set, nil)
			defer stub1.Reset()
			stub2 := stubby.StubFunc(&jwsVerifyWithJWK, nil, nil)
			defer stub2.Reset()

			// validate token
			tokenDone, err := Validate(db, jwkEndpoint, audience, ctx)
			So(err, ShouldBeNil)
			So(tokenDone, ShouldResemble, token)

			// check db for saved token
			err = db.View(func(tx *buntdb.Tx) error {
				_, err := tx.Get(jwtToken)
				if err != nil {
					return err
				}
				return nil
			})
			So(err, ShouldBeNil)

			// validate again to test key caching
			tokenDone, err = Validate(db, jwkEndpoint, audience, ctx)
			So(err, ShouldBeNil)
			So(tokenDone, ShouldResemble, token)
		})

		Convey("Success - fresh key on first request - net/http", func() {
			// set vars
			jwkEndpoint := "https://example.com/"
			audience := "https://httpbin.org/"

			// Timestamp the beginning.
			now := time.Now()
			// Define a signer.
			hs256 := jwt.NewHS256("secret")
			jot := &jwt.JWT{
				Issuer:         "https://example.auth0.com/",
				Subject:        "user@email.com",
				Audience:       audience,
				ExpirationTime: now.Add(24 * 30 * 12 * time.Hour).Unix(),
				NotBefore:      now.Add(time.Duration(-10) * time.Minute).Unix(),
				IssuedAt:       now.Unix(),
			}
			jot.SetAlgorithm(hs256)
			jot.SetKeyID("QkZBNjE4MzI3MTQwMEZCNDg0RjIyMDgyMDBFMTZFRUIwOEE5NTAxNg")

			payload, err := jwt.Marshal(jot)
			So(err, ShouldBeNil)

			tokenBytes, err := hs256.Sign(payload)
			So(err, ShouldBeNil)
			jwtToken := cast.ToString(tokenBytes)

			ctx, err := http.NewRequest("GET", "http://example.com", nil)
			So(err, ShouldBeNil)
			ctx.Header.Add("Authorization", "Bearer "+jwtToken)

			token, err := verifyToken(jwtToken)
			So(err, ShouldBeNil)

			// stub out needed functions with success factors
			set, err := jwk.ParseString(jwks)
			So(err, ShouldBeNil)
			stub1 := stubby.StubFunc(&jwkFetch, set, nil)
			defer stub1.Reset()
			stub2 := stubby.StubFunc(&jwsVerifyWithJWK, nil, nil)
			defer stub2.Reset()

			// validate token
			tokenDone, err := ValidateNet(db, jwkEndpoint, audience, ctx)
			So(err, ShouldBeNil)
			So(tokenDone, ShouldResemble, token)
		})

		Convey("Failure - bad Bearer token - net/http", func() {
			// set vars
			jwkEndpoint := "https://example.com/"
			audience := "https://httpbin.org/"

			ctx, err := http.NewRequest("GET", "http://example.com", nil)
			So(err, ShouldBeNil)
			ctx.Header.Add("Authorization", "Bearer")

			// validate token
			_, err = ValidateNet(db, jwkEndpoint, audience, ctx)
			So(err, ShouldBeError)
		})

		Convey("Failure - expired key provided on first request", func() {
			// set vars
			jwkEndpoint := "https://example.com/"
			audience := "https://httpbin.org/"

			// Timestamp the beginning.
			now := time.Now()
			// Define a signer.
			hs256 := jwt.NewHS256("secret")
			jot := &jwt.JWT{
				Issuer:         "https://example.auth0.com/",
				Subject:        "user@email.com",
				Audience:       audience,
				ExpirationTime: now.Add(time.Duration(-10) * time.Minute).Unix(),
				NotBefore:      now.Add(time.Duration(-10) * time.Minute).Unix(),
				IssuedAt:       now.Unix(),
			}
			jot.SetAlgorithm(hs256)
			jot.SetKeyID("QkZBNjE4MzI3MTQwMEZCNDg0RjIyMDgyMDBFMTZFRUIwOEE5NTAxNg")

			payload, err := jwt.Marshal(jot)
			So(err, ShouldBeNil)

			tokenBytes, err := hs256.Sign(payload)
			So(err, ShouldBeNil)
			jwtToken := cast.ToString(tokenBytes)

			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.Add("Authorization", "Bearer "+jwtToken)

			// stub out needed functions with success factors
			set, err := jwk.ParseString(jwks)
			So(err, ShouldBeNil)
			stub1 := stubby.StubFunc(&jwkFetch, set, nil)
			defer stub1.Reset()
			stub2 := stubby.StubFunc(&jwsVerifyWithJWK, nil, nil)
			defer stub2.Reset()

			_, err = Validate(db, jwkEndpoint, audience, ctx)
			So(err, ShouldBeError)

			// check db for saved token
			err = db.View(func(tx *buntdb.Tx) error {
				_, err := tx.Get(jwtToken)
				if err != nil {
					return err
				}
				return nil
			})
			So(err, ShouldBeError)
		})

		Convey("Failure - audience does not match", func() {
			// set vars
			jwkEndpoint := "https://example.com/"
			audience := "https://httpbin.org/"

			// Timestamp the beginning.
			now := time.Now()
			// Define a signer.
			hs256 := jwt.NewHS256("secret")
			jot := &jwt.JWT{
				Issuer:         "https://example.auth0.com/",
				Subject:        "user@email.com",
				Audience:       "foobar",
				ExpirationTime: now.Add(24 * 30 * 12 * time.Hour).Unix(),
				NotBefore:      now.Add(time.Duration(-10) * time.Minute).Unix(),
				IssuedAt:       now.Unix(),
			}
			jot.SetAlgorithm(hs256)
			jot.SetKeyID("QkZBNjE4MzI3MTQwMEZCNDg0RjIyMDgyMDBFMTZFRUIwOEE5NTAxNg")

			payload, err := jwt.Marshal(jot)
			So(err, ShouldBeNil)

			tokenBytes, err := hs256.Sign(payload)
			So(err, ShouldBeNil)
			jwtToken := cast.ToString(tokenBytes)

			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.Add("Authorization", "Bearer "+jwtToken)

			// stub out needed functions with success factors
			set, err := jwk.ParseString(jwks)
			So(err, ShouldBeNil)
			stub1 := stubby.StubFunc(&jwkFetch, set, nil)
			defer stub1.Reset()
			stub2 := stubby.StubFunc(&jwsVerifyWithJWK, nil, nil)
			defer stub2.Reset()

			// validate token
			_, err = Validate(db, jwkEndpoint, audience, ctx)
			So(err, ShouldBeError)
		})

		Convey("Failure - Bearer token not defined", func() {
			// set vars
			jwkEndpoint := "https://example.com/"
			audience := "https://httpbin.org/"

			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.Add("Authorization", "Bearer")

			// validate token
			_, err = Validate(db, jwkEndpoint, audience, ctx)
			So(err, ShouldBeError)
		})

		Convey("Failure - Bearer not defined", func() {
			// set vars
			jwkEndpoint := "https://example.com/"
			audience := "https://httpbin.org/"

			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.Add("Authorization", "Foobar 123")

			// validate token
			_, err = Validate(db, jwkEndpoint, audience, ctx)
			So(err, ShouldBeError)
		})

		Convey("Failure - Authorization Header not defined", func() {
			// set vars
			jwkEndpoint := "https://example.com/"
			audience := "https://httpbin.org/"

			ctx := &fasthttp.RequestCtx{}

			// validate token
			_, err = Validate(db, jwkEndpoint, audience, ctx)
			So(err, ShouldBeError)
		})
	})

	Convey("Unit Tests", t, func() {

		Convey("GetScopes - Success", func() {
			jwtToken := `eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik1FTTNNRFEzTkRBME56RkJRME13TkVJNVFVSTVPVVkyTWpNNFJEWTRSamRDUXpKR1JrTTFOQSJ9.eyJpc3MiOiJodHRwczovL2JldmFuaHVudC5hdXRoMC5jb20vIiwic3ViIjoiZ2l0aHVifDg5MjQwNCIsImF1ZCI6WyJodHRwczovL2h0dHBiaW4ub3JnLyIsImh0dHBzOi8vYmV2YW5odW50LmF1dGgwLmNvbS91c2VyaW5mbyJdLCJpYXQiOjE1MzY2NjI4MjAsImV4cCI6MTUzNjY3MDAyMCwiYXpwIjoiWFZBSThLdWk4OW5KNE1yUnBTOExiZmJuenhnT0lLUjQiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIGdldDpnZXQifQ.un8WKaw9cshRHEXIlVzk4HO1BSBwoWKv_sFkS_N4youb7rX7t54WcH3zSSjuAGbIW9u8fbjhPBLRK4PF44xf-X9j3Xc0f7GRXztET7zWpQ6see9KUeRICFp0t5kppnj3E_lZZucr6c8El3IJT8wiojh3027zCEzMfIQhpDO81hF1rMbSmz188pUDXp6HlL84HvIF8OjIjDXj0H3MLBR51G4n_aKPzxI8qDGR5-xyABAmlLnbHb1xjXNwEh3tsiOREiJjGw7jx5IeHSOOvInTlBMzQ7XvTHDPYWLpRfGCJBva0lNJ_BqYbdBUd044a2GBoOuCqKnfzFPV664fg-5R-w`
			token, err := jwxt.ParseString(jwtToken)
			So(err, ShouldBeNil)
			scopes, err := GetScopes(token)
			So(err, ShouldBeNil)
			scopesExp := []string{"openid", "profile", "email", "get:get"}
			So(scopes, ShouldResemble, scopesExp)
		})

		Convey("GetScopes - Failure - valid token no scopes", func() {
			jwtToken := `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM`
			token, err := jwxt.ParseString(jwtToken)
			So(err, ShouldBeNil)
			_, err = GetScopes(token)
			So(err, ShouldBeError)
		})

		Convey("verifyToken - failure: jwt is invalid", func() {
			_, err := verifyToken("123")
			So(err, ShouldBeError)
		})

		Convey("validateToken - failure: jwk.Fetch errors", func() {
			stub1 := stubby.StubFunc(&jwkFetch, nil, errors.New("failure"))
			defer stub1.Reset()
			_, err := validateToken("", "")
			So(err, ShouldBeError)
		})

		Convey("validateToken - failure: jws.VerifyWithJWK errors", func() {
			// stub out needed functions with success factors
			set, err := jwk.ParseString(jwks)
			So(err, ShouldBeNil)
			stub1 := stubby.StubFunc(&jwkFetch, set, nil)
			defer stub1.Reset()
			stub2 := stubby.StubFunc(&jwsVerifyWithJWK, nil, errors.New("error"))
			defer stub2.Reset()
			_, err = validateToken("", "")
			So(err, ShouldBeError)
		})
	})
}
