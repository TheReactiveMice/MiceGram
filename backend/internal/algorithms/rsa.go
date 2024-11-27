package algorithms

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
)

func RSA_PrivateKeyToBytes(privateKey *rsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS1PrivateKey(privateKey), nil
}

func RSA_PrivateKeyFromBytes(data []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(data)
}

func RSA_PublicKeyToBytes(publicKey *rsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(publicKey)
}

func RSA_PublicKeyFromBytes(data []byte) (*rsa.PublicKey, error) {
	pubKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPubKey, nil
}

func RSA_GenerateKeys(length int) ([]byte, []byte) {
	private_key, err := rsa.GenerateKey(rand.Reader, length)

	if err != nil {
		return nil, nil
	}

	private_key_bytes, err := RSA_PrivateKeyToBytes(private_key)

	if err != nil {
		return nil, nil
	}

	public_key_bytes, err := RSA_PublicKeyToBytes(&private_key.PublicKey)

	if err != nil {
		return nil, nil
	}

	return private_key_bytes, public_key_bytes
}

func RSA_Encrypt(text []byte, key []byte) ([]byte, error) {
	pubKey, err := RSA_PublicKeyFromBytes(key)

	if err != nil {
		return nil, err
	}

	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, text)

	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

func RSA_Decrypt(text []byte, key []byte) ([]byte, error) {
	privKey, err := RSA_PrivateKeyFromBytes(key)

	if err != nil {
		return nil, err
	}

	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, text)

	if err != nil {
		return nil, err
	}

	return decrypted, nil
}
