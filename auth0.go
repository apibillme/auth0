package auth0

import (
	"errors"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/jws"

	"github.com/lestrrat-go/jwx/jwk"

	"github.com/spf13/cast"
	"github.com/valyala/fasthttp"

	"github.com/lestrrat-go/jwx/jwt"

	"github.com/tidwall/buntdb"
)

func validateToken(url string, jwtToken string) (*jwt.Token, error) {
	// get JWKs and validate them against JWT token
	set, err := jwk.Fetch(url)
	matches := 0
	for _, key := range set.Keys {
		_, err = jws.VerifyWithJWK([]byte(jwtToken), key)
		if err == nil {
			matches++
		}
	}

	// if JWT validated then verify token
	if matches > 0 {
		return verifyToken(jwtToken)
	}

	// token is invalid
	return nil, errors.New("token is invalid")
}

func verifyToken(jwtToken string) (*jwt.Token, error) {
	// parse & verify claims of JWT token
	token, err := jwt.ParseString(jwtToken)
	if err != nil {
		return nil, err
	}
	err = token.Verify()
	if err != nil {
		return nil, err
	}
	return token, nil
}

func extractBearerTokenNet(req *http.Request) []string {
	bearerToken := req.Header.Get("Authorization")
	return strings.Split(bearerToken, " ")
}

func extractBearerToken(req *fasthttp.RequestCtx) []string {
	bearerTokenBytes := req.Request.Header.Peek("Authorization")
	bearerToken := cast.ToString(bearerTokenBytes)
	return strings.Split(bearerToken, " ")
}

func verifyBearerToken(tokenParts []string) (string, error) {
	if len(tokenParts) < 2 {
		return "", errors.New("Authorization header must have a Bearer token")
	}
	if tokenParts[0] != "Bearer" {
		return "", errors.New("Authorization header must have a Bearer token")
	}
	return tokenParts[1], nil
}

func getJwtToken(req *fasthttp.RequestCtx) (string, error) {
	tokenParts := extractBearerToken(req)
	return verifyBearerToken(tokenParts)
}

func getJwtTokenNet(req *http.Request) (string, error) {
	tokenParts := extractBearerTokenNet(req)
	return verifyBearerToken(tokenParts)
}

func processToken(db *buntdb.DB, jwtToken string, audience string, url string) (*jwt.Token, error) {
	// check if token is in db
	err := db.View(func(tx *buntdb.Tx) error {
		_, err := tx.Get(jwtToken)
		if err != nil {
			return err
		}
		return nil
	})

	// if not then validate & verify token and save in db
	if err != nil {
		token, err := validateToken(url, jwtToken)
		if err != nil {
			return nil, err
		}
		// validate audience
		if token.Audience() != audience {
			return nil, errors.New("audience is not valid")
		}
		err = db.Update(func(tx *buntdb.Tx) error {
			_, _, err := tx.Set(jwtToken, jwtToken, nil)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// if so then only verify token
	token, err := verifyToken(jwtToken)

	// if token cannot be verfied then delete it from db
	if err != nil {
		err = db.Update(func(tx *buntdb.Tx) error {
			_, err = tx.Delete(jwtToken)
			if err != nil {
				return err
			}
			return nil
		})
		return nil, err
	}

	// if everything is good return token
	return token, nil
}

// ValidateAuth0 - validate with JWK & JWT Auth0 & audience for fasthttp
func ValidateAuth0(db *buntdb.DB, url string, audience string, req *fasthttp.RequestCtx) (*jwt.Token, error) {
	// extract token from header
	jwtToken, err := getJwtToken(req)
	if err != nil {
		return nil, err
	}
	// process token
	return processToken(db, jwtToken, audience, url)
}

// ValidateAuth0Net - validate with JWK & JWT Auth0 & audience for net/http
func ValidateAuth0Net(db *buntdb.DB, url string, audience string, req *http.Request) (*jwt.Token, error) {
	// extract token from header
	jwtToken, err := getJwtTokenNet(req)
	if err != nil {
		return nil, err
	}
	// process token
	return processToken(db, jwtToken, audience, url)
}
