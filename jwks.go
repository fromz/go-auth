package go_auth

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"github.com/fromz/go-jwks"
	"gopkg.in/square/go-jose.v2/json"
	"io/ioutil"
	"time"

	"gopkg.in/square/go-jose.v2"
)

// JWKSClient returns a new JWKS Client using provided source, refresh, and expiration
func JWKSClient(s jwks.JWKSSource) jwks.JWKSClient {
	return jwks.NewDefaultClient(
		s,
		time.Hour,    // Refresh keys every 1 hour
		12*time.Hour, // Expire keys after 12 hours
	)
}

// JWKSWebSource returns a jwks source which fetches from a URL
func JWKSWebSource(url string) *jwks.WebSource {
	return jwks.NewWebSource(url)
}

// JWKSFileSource returns a jwks source which fetches from a file, for development
func JWKSFileSource(filepath string) (*jwks.DummySource, error) {
	b, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return JWKSByteSource(b)
}

// JWKSByteSource returns a JWKS dummy source using bytes
func JWKSByteSource(b []byte) (*jwks.DummySource, error) {
	var keyset jose.JSONWebKeySet
	if err := json.Unmarshal(b, &keyset); err != nil {
		return nil, err
	}
	return jwks.NewDummySource(&keyset), nil
}

// GenerateJWKSWithNewRSAKeys returns a new JWKS with a new set of keys
func GenerateJWKSWithNewRSAKeys(publicKeyID string, privateKeyID string) (jose.JSONWebKeySet, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}

	pub := jose.JSONWebKey{Key: key.Public(), KeyID: publicKeyID, Algorithm: string(jose.RS256), Use: "sig"}
	priv := jose.JSONWebKey{Key: key, KeyID: privateKeyID, Algorithm: string(jose.RS256), Use: "sig"}

	if priv.IsPublic() || !pub.IsPublic() || !priv.Valid() || !pub.Valid() {
		return jose.JSONWebKeySet{}, errors.New("generated keys are invalid")
	}

	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			priv,
			pub,
		},
	}, nil
}