package main

import (
	"bufio"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
	"os"
)

// copied from kubernetes/kubernetes#78502
func keyIDFromPublicKey(publicKey interface{}) (string, error) {
	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to serialize public key to DER format: %v", err)
	}

	hasher := crypto.SHA256.New()
	hasher.Write(publicKeyDERBytes)
	publicKeyDERHash := hasher.Sum(nil)

	keyID := base64.RawURLEncoding.EncodeToString(publicKeyDERHash)

	return keyID, nil
}

type KeyResponse struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

func readKey(content []byte) ([]byte, error) {
	var response []byte
	block, _ := pem.Decode(content)
	if block == nil {
		return response, errors.Errorf("Error decoding PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return response, errors.Wrapf(err, "Error parsing key content")
	}
	switch pubKey.(type) {
	case *rsa.PublicKey:
	default:
		return response, errors.New("Public key was not RSA")
	}

	var alg jose.SignatureAlgorithm
	switch pubKey.(type) {
	case *rsa.PublicKey:
		alg = jose.RS256
	default:
		return response, fmt.Errorf("invalid public key type %T, must be *rsa.PrivateKey", pubKey)
	}

	kid, err := keyIDFromPublicKey(pubKey)
	if err != nil {
		return response, err
	}

	var keys []jose.JSONWebKey
	keys = append(keys, jose.JSONWebKey{
		Key:       pubKey,
		KeyID:     kid,
		Algorithm: string(alg),
		Use:       "sig",
	})
	keys = append(keys, jose.JSONWebKey{
		Key:       pubKey,
		Algorithm: string(alg),
		Use:       "sig",
	})

	keyResponse := KeyResponse{Keys: keys}
	return json.Marshal(keyResponse)
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	var res map[string]string
	for scanner.Scan() {
		if err := json.Unmarshal([]byte(scanner.Text()), &res); err != nil {
			panic(err)
		}

		bb := []byte(res["pub_key"])
		output, err := readKey(bb)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		j := map[string]string{"jwks": string(output)}
		jm, _ := json.Marshal(j)
		fmt.Println(string(jm))
	}
}
