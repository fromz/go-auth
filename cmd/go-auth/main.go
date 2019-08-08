package main

import (
	"encoding/json"
	"github.com/sirupsen/logrus"
	"github.com/square/go-jose"
	"io/ioutil"
	"net/http"
	"os"
)

var log *logrus.Logger

func makeJwks() {

}

// Intended to be a stand-in replacement for AuthO's JWKs endpoint, for development purposes only.
func main() {
	log = logrus.New()

	// todo: generate this on the fly if file not provided
	// bash `jose-util generate-key --alg=RS256 --use=sig` will generate two jwk files, merge them together into jwks.json
	b, err := ioutil.ReadFile("../../jwks.json")
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(b, &jwks); err != nil {
		log.Error(err)
		os.Exit(1)
	}

	// extract private and public jwk for use in signing JWTs and generating a public jwks
	var prjwk jose.JSONWebKey
	var pbjwk jose.JSONWebKey
	for _, jwk := range jwks.Keys {
		if jwk.IsPublic() {
			pbjwk = jwk
			continue
		}
		prjwk = jwk
	}
	if false == prjwk.Valid() {
		log.Error("Could not find valid private jwk in jwks")
		os.Exit(1)
	}
	if false == pbjwk.Valid() {
		log.Error("Could not find valid public jwk in jwks")
		os.Exit(1)
	}

	// generate public jwks
	pbjwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{pbjwk},
	}
	pbjwksb, err := json.Marshal(pbjwks)
	if err != nil {
		log.Error("Could not marshal public jwk to JSON")
		log.Error(err)
		os.Exit(1)
	}

	// Endpoint for public jwks
	http.HandleFunc("/.well-known/jwks.json", func (w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(pbjwksb)
	})

	// Prepare a JWT signer for the oauth/token endpoint
	//sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: prjwk.Key}, (&jose.SignerOptions{}).WithType("JWT"))
	//if err != nil {
	//	panic(err)
	//}

	// Generate a token for testing purposes
	// TODO: Let users specifcy claims in the POST request
	http.HandleFunc("/oauth/token", func (w http.ResponseWriter, r *http.Request) {
		//cl := jwt.Claims{
		//	Subject:   "9999",
		//	Issuer:    "auth",
		//	Expiry: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour)),
		//	Audience:  jwt.Audience{"admin"},
		//}
		//raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
		//if err != nil {
		//	w.WriteHeader(http.StatusInternalServerError)
		//	w.Write([]byte(err.Error()))
		//}
		//w.Header().Set("Content-Type", "application/json")
		//w.Write([]byte(raw))
	})

	// Start web cookies
	if err := http.ListenAndServe(":8011", nil); err != nil {
		log.Error(err)
	}

}
