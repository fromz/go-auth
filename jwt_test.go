package go_auth

import (
	"fmt"
	"github.com/fromz/go-jwks"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"testing"
)

func generateJwksClientWithNewRSAKeys() (jwks.JWKSClient, error) {
	jwkKeySet, err := GenerateJWKSWithNewRSAKeys("pub", "priv")
	if err != nil {
		return nil, err
	}

	return JWKSClient(&jwks.DummySource{
		Jwks: &jwkKeySet,
	}), nil
}

func TestJwtVerifier_Verify(t *testing.T) {
	// generate a new dummy JWKs Client with fresh RSA keys
	dummyClient, err := generateJwksClientWithNewRSAKeys()
	if err != nil {
		t.Error(err)
		return
	}

	// extract the key from the JWKS
	pk, err := dummyClient.GetSignatureKey("priv")
	if err != nil {
		t.Error(err)
		return
	}

	// create a Square.jose RSA signer
	rsaSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: pk}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Error(err)
		return
	}

	// sign some claims to make a JWT
	rawJWT, err := jwt.Signed(rsaSigner).Claims(jwt.Claims{}).CompactSerialize()
	if err != nil {
		t.Error(err)
		return
	}

	// verify the JWT using a JWKS client
	j := NewJwtVerifier(dummyClient, "pub")
	destClaims := UserClaims{}
	err = j.Verify(rawJWT, &destClaims)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestJwtVerifier_VerifyClaimsAreExtracted(t *testing.T) {
	// generate a new dummy JWKs Client with fresh RSA keys
	dummyClient, err := generateJwksClientWithNewRSAKeys()
	if err != nil {
		t.Error(err)
		return
	}

	// extract the key from the JWKS
	pk, err := dummyClient.GetSignatureKey("priv")
	if err != nil {
		t.Error(err)
		return
	}

	// create a Square.jose RSA signer
	rsaSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: pk}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Error(err)
		return
	}

	// sign some claims to make a JWT
	rawJWT, err := jwt.Signed(rsaSigner).Claims(jwt.Claims{
		Subject: "Reginald",
	}).CompactSerialize()
	if err != nil {
		t.Error(err)
		return
	}

	// verify the JWT using a JWKS client
	j := NewJwtVerifier(dummyClient, "pub")
	destClaims := jwt.Claims{}
	fmt.Println(rawJWT)
	err = j.Verify(rawJWT, &destClaims)
	if err != nil {
		t.Error(err)
		return
	}

	if destClaims.Subject != "Reginald" {
		t.Errorf("Expected subject as Reginald got %s", destClaims.Subject)
	}
}

func TestJwtVerifier_VerifyFailsWhenInvalidSignature(t *testing.T) {
	// generate a new dummy JWKs Client with fresh RSA keys
	invalidJWKSClient, err := generateJwksClientWithNewRSAKeys()
	if err != nil {
		t.Error(err)
		return
	}

	// extract the key from the JWKS
	pk, err := invalidJWKSClient.GetSignatureKey("priv")
	if err != nil {
		t.Error(err)
		return
	}

	// create a Square.jose RSA signer
	rsaSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: pk}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Error(err)
		return
	}

	// sign some claims to make a JWT
	rawJWT, err := jwt.Signed(rsaSigner).Claims(jwt.Claims{}).CompactSerialize()
	if err != nil {
		t.Error(err)
		return
	}

	// make a new JWKS to attempt to verify
	validJWKSClient, err := generateJwksClientWithNewRSAKeys()
	if err != nil {
		t.Error(err)
		return
	}

	// verify the JWT using a JWKS client
	j := NewJwtVerifier(validJWKSClient, "pub")
	err = j.Verify(rawJWT)
	if err == nil {
		t.Errorf("Expected verify to fail, got pass")
	}
}