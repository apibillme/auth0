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
			jwkEndpoint := "https://example.auth0.com/jwks.json"
			audience := "https://httpbin.org/"
			issuer := "https://example.auth0.com/"

			// Timestamp the beginning.
			now := time.Now()
			// Define a signer.
			hs256 := jwt.NewHS256("secret")
			jot := &jwt.JWT{
				Issuer:         issuer,
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
			tokenDone, err := Validate(db, jwkEndpoint, audience, issuer, ctx)
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
			tokenDone, err = Validate(db, jwkEndpoint, audience, issuer, ctx)
			So(err, ShouldBeNil)
			So(tokenDone, ShouldResemble, token)
		})

		Convey("Success - fresh key on first request - net/http", func() {
			// set vars
			jwkEndpoint := "https://example.auth0.com/jwks.json"
			audience := "https://httpbin.org/"
			issuer := "https://example.auth0.com/"

			// Timestamp the beginning.
			now := time.Now()
			// Define a signer.
			hs256 := jwt.NewHS256("secret")
			jot := &jwt.JWT{
				Issuer:         issuer,
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
			tokenDone, err := ValidateNet(db, jwkEndpoint, audience, issuer, ctx)
			So(err, ShouldBeNil)
			So(tokenDone, ShouldResemble, token)
		})

		Convey("Failure - bad Bearer token - net/http", func() {
			// set vars
			jwkEndpoint := "https://example.auth0.com/jwks.json"
			audience := "https://httpbin.org/"
			issuer := ""

			ctx, err := http.NewRequest("GET", "http://example.com", nil)
			So(err, ShouldBeNil)
			ctx.Header.Add("Authorization", "Bearer")

			// validate token
			_, err = ValidateNet(db, jwkEndpoint, audience, issuer, ctx)
			So(err, ShouldBeError)
		})

		Convey("Failure - expired key provided on first request", func() {
			// set vars
			jwkEndpoint := "https://example.auth0.com/jwks.json"
			audience := "https://httpbin.org/"
			issuer := "https://example.auth0.com/"

			// Timestamp the beginning.
			now := time.Now()
			// Define a signer.
			hs256 := jwt.NewHS256("secret")
			jot := &jwt.JWT{
				Issuer:         issuer,
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

			_, err = Validate(db, jwkEndpoint, audience, issuer, ctx)
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
			jwkEndpoint := "https://example.auth0.com/jwks.json"
			audience := "https://httpbin.org/"
			issuer := "https://example.auth0.com/"

			// Timestamp the beginning.
			now := time.Now()
			// Define a signer.
			hs256 := jwt.NewHS256("secret")
			jot := &jwt.JWT{
				Issuer:         issuer,
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
			_, err = Validate(db, jwkEndpoint, audience, issuer, ctx)
			So(err, ShouldBeError)
		})

		Convey("Failure - issuer does not match", func() {
			// set vars
			jwkEndpoint := "https://example.auth0.com/jwks.json"
			audience := "https://httpbin.org/"
			issuer := "https://example.auth0.com/"

			// Timestamp the beginning.
			now := time.Now()
			// Define a signer.
			hs256 := jwt.NewHS256("secret")
			jot := &jwt.JWT{
				Issuer:         "foobar",
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

			// stub out needed functions with success factors
			set, err := jwk.ParseString(jwks)
			So(err, ShouldBeNil)
			stub1 := stubby.StubFunc(&jwkFetch, set, nil)
			defer stub1.Reset()
			stub2 := stubby.StubFunc(&jwsVerifyWithJWK, nil, nil)
			defer stub2.Reset()

			// validate token
			_, err = Validate(db, jwkEndpoint, audience, issuer, ctx)
			So(err, ShouldBeError)
		})

		Convey("Failure - Bearer token not defined", func() {
			// set vars
			jwkEndpoint := "https://example.auth0.com/jwks.json"
			audience := "https://httpbin.org/"
			issuer := ""

			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.Add("Authorization", "Bearer")

			// validate token
			_, err = Validate(db, jwkEndpoint, audience, issuer, ctx)
			So(err, ShouldBeError)
		})

		Convey("Failure - Bearer not defined", func() {
			// set vars
			jwkEndpoint := "https://example.auth0.com/jwks.json"
			audience := "https://httpbin.org/"
			issuer := "https://example.auth0.com/"

			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.Add("Authorization", "Foobar 123")

			// validate token
			_, err = Validate(db, jwkEndpoint, audience, issuer, ctx)
			So(err, ShouldBeError)
		})

		Convey("Failure - Authorization Header not defined", func() {
			// set vars
			jwkEndpoint := "https://example.auth0.com/jwks.json"
			audience := "https://httpbin.org/"
			issuer := "https://example.auth0.com/"

			ctx := &fasthttp.RequestCtx{}

			// validate token
			_, err = Validate(db, jwkEndpoint, audience, issuer, ctx)
			So(err, ShouldBeError)
		})
	})

	Convey("Unit Tests", t, func() {

		jwtTokenFull := `eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik1FTTNNRFEzTkRBME56RkJRME13TkVJNVFVSTVPVVkyTWpNNFJEWTRSamRDUXpKR1JrTTFOQSJ9.eyJodHRwczovL2h0dHBiaW4ub3JnL2VtYWlsIjoiYmV2YW5AYmV2YW5odW50LmNvbSIsImlzcyI6Imh0dHBzOi8vYmV2YW5odW50LmF1dGgwLmNvbS8iLCJzdWIiOiJnaXRodWJ8ODkyNDA0IiwiYXVkIjpbImh0dHBzOi8vaHR0cGJpbi5vcmcvIiwiaHR0cHM6Ly9iZXZhbmh1bnQuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTUzNjY5NjQ3MCwiZXhwIjoxNTM2NzAzNjcwLCJhenAiOiJYVkFJOEt1aTg5bko0TXJScFM4TGJmYm56eGdPSUtSNCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwgZ2V0OmdldCBnZXQ6dXNlcnMifQ.LLqJwOf5dzKyotzyZAkhXwRe_WAAg2D8mqAoRjRXKaJm1AcBgInyN-8zqVAULGXw5qJ2XvqF4VUaBFzdoo3rxobjp_XbsFwa7o3cSvup-RKmbNr7bsCCtgHUILzYenugNHrszgvUNyrDtDZjtwINhLTVrnK6R1CXWKzWB3E0uH2W7Lwcl0G2nFYltYZU8BHJFje0a_x3mn2CIgcqIhjgKdP4KZZZhuu2SrIzqATHkt9SksQu8t4uIKtFzT-fl5gHHBRNwN-p0xotpHO-4Zqt901U6DNF-XmGXbprXWeiBt9PydC7XQ36txy9poLlrFdGkBMh_Cm6LQplK7WxFCLDMg`
		jwtTokenNoScopes := `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM`

		Convey("GetEmail - Success", func() {
			token, err := jwxt.ParseString(jwtTokenFull)
			So(err, ShouldBeNil)
			audience := `https://httpbin.org/`
			email, err := GetEmail(token, audience)
			So(err, ShouldBeNil)
			So(email, ShouldResemble, "bevan@bevanhunt.com")
		})

		Convey("GetURLScopes - Success", func() {
			token, err := jwxt.ParseString(jwtTokenFull)
			So(err, ShouldBeNil)
			scopes, err := GetURLScopes(token)
			So(err, ShouldBeNil)
			scopesExp := []URLScope{
				URLScope{
					Method: "get",
					URL:    "get",
				},
				URLScope{
					Method: "get",
					URL:    "users",
				},
			}
			So(scopes, ShouldResemble, scopesExp)
		})

		Convey("GetURLScopes - Failure - no scopes", func() {
			token, err := jwxt.ParseString(jwtTokenNoScopes)
			So(err, ShouldBeNil)
			_, err = GetURLScopes(token)
			So(err, ShouldBeError)
		})

		Convey("GetScopes - Success", func() {
			token, err := jwxt.ParseString(jwtTokenFull)
			So(err, ShouldBeNil)
			scopes, err := GetScopes(token)
			So(err, ShouldBeNil)
			scopesExp := []string{"openid", "profile", "email", "get:get", "get:users"}
			So(scopes, ShouldResemble, scopesExp)
		})

		Convey("GetScopes - Failure - valid token no scopes", func() {
			token, err := jwxt.ParseString(jwtTokenNoScopes)
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
