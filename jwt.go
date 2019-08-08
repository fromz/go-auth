package go_auth

import (
	"fmt"
	"github.com/fromz/go-jwks"
	"gopkg.in/square/go-jose.v2/jwt"
)

// JwtVerifier hides away some of the complexity of verifying JWTs
type JwtVerifier struct {
	keyId string
	jwksClient jwks.JWKSClient
}

// Verify takes a JWT and returns whether or not it is currently valid, given jwks
func (j JwtVerifier) Verify(rawJWT string, dest ...interface{}) error {
	k, err := j.jwksClient.GetSignatureKey(j.keyId)
	if err != nil {
		return fmt.Errorf("getting signature key: %s", err.Error())
	}

	parsedJWT, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		return fmt.Errorf("parsing JWT: %s", err.Error())
	}

	if err := parsedJWT.Claims(k, dest...); err != nil {
		return fmt.Errorf("extracting claims with key: %s", err.Error())
	}

	return nil
}

func NewJwtVerifier(jwksClient jwks.JWKSClient, keyId string) JwtVerifier {
	return JwtVerifier{
		jwksClient: jwksClient,
		keyId: keyId,
	}
}
