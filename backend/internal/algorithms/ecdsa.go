package algorithms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
)

type PublicKeyBytes struct {
	X, Y *big.Int
}

func ECDSA_PrivateKeyToBytes(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalECPrivateKey(privateKey)
}

func ECDSA_PrivateKeyFromBytes(data []byte) (*ecdsa.PrivateKey, error) {
	return x509.ParseECPrivateKey(data)
}

func ECDSA_PublicKeyToBytes(publicKey *ecdsa.PublicKey) ([]byte, error) {
	asn1Bytes, err := asn1.Marshal(PublicKeyBytes{X: publicKey.X, Y: publicKey.Y})
	if err != nil {
		return nil, err
	}
	return asn1Bytes, nil
}

func ECDSA_PublicKeyFromBytes(data []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	var pubKeyBytes PublicKeyBytes
	_, err := asn1.Unmarshal(data, &pubKeyBytes)
	if err != nil {
		return nil, err
	}

	if pubKeyBytes.X == nil || pubKeyBytes.Y == nil {
		return nil, errors.New("invalid public key data")
	}

	return &ecdsa.PublicKey{Curve: curve, X: pubKeyBytes.X, Y: pubKeyBytes.Y}, nil
}

func ECDSA_GenerateKeys() ([]byte, []byte) {
	private_key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	if err != nil {
		return nil, nil
	}

	private_key_bytes, err := ECDSA_PrivateKeyToBytes(private_key)

	if err != nil {
		return nil, nil
	}

	public_key_bytes, err := ECDSA_PublicKeyToBytes(&private_key.PublicKey)

	if err != nil {
		return nil, nil
	}

	return private_key_bytes, public_key_bytes
}

func ECDSA_Sign(text []byte, key []byte) ([]byte, error) {
	private_key, err := ECDSA_PrivateKeyFromBytes(key)
	if err != nil {
		return nil, err
	}

	sha256sum := sha256.New().Sum(text)
	return ecdsa.SignASN1(rand.Reader, private_key, sha256sum)
}

func ECDSA_Verify(text []byte, key []byte, signature []byte) (bool, error) {
	public_key, err := ECDSA_PublicKeyFromBytes(key, elliptic.P384())
	if err != nil {
		return false, err
	}

	sha256sum := sha256.New().Sum(text)
	return ecdsa.VerifyASN1(public_key, sha256sum, signature), nil
}
