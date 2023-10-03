package main

import (
	"context"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

func validateJWT(ctx context.Context, cfg *config, token string) (bool, error) {
	// Fetch the JWKS from the issuer's JWKS endpoint
	jwksURL := fmt.Sprintf("%s/.well-known/jwks", cfg.Issuer)
	set, err := jwk.Fetch(ctx, jwksURL)
	if err != nil {
		return false, fmt.Errorf("Error fetching JWKS: %v", err)
	}

	// Define the key function for token validation
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid claim not found in token header")
		}

		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, fmt.Errorf("alg claim not found in token header")
		}

		tokenClaims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("unable to convert token claims into maps.")
		}

		audiences, ok := tokenClaims["aud"].([]interface{})
		if !ok {
			return nil, fmt.Errorf("unable to find valid audience in jwt claims.")
		}

		audienceMatched := false
		for _, aud := range audiences {
			audStr, ok := aud.(string)
			if !ok {
				return nil, fmt.Errorf("found an illegal audience in the in jwt's audience list.")
			}

			if cfg.Aud == audStr {
				audienceMatched = true
				break
			}
		}

		if !audienceMatched {
			return nil, fmt.Errorf("the audience in the token doesn't match the expected subject.")
		}

		// Find the key with the matching "kid" in the JWKS
		key, ok := set.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("Key with kid %s not found in JWKS", kid)
		}

		if alg != key.Algorithm() {
			return nil, fmt.Errorf("The alg in token ('%s') doesn't match with alg not found in JWKS ('%s')", alg, key.Algorithm())
		}

		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return false, fmt.Errorf("failed to create public key: %v", err)
		}

		return rawKey, nil
	}

	// Define the JWT claims structure with the expected values
	claims := jwt.MapClaims{
		"iss": cfg.Issuer,
		"aud": cfg.Aud,
		"exp": time.Now().Add(time.Hour * 1).Unix(),
	}

	// Parse the token
	jwtToken, err := jwt.ParseWithClaims(token, claims, keyFunc)
	if err != nil {
		return false, fmt.Errorf("Error parsing token: %v", err)
	}

	return jwtToken.Valid, nil
}
