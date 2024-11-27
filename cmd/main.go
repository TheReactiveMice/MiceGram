package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"pizdec/internal/algorithms"
	"pizdec/internal/ipc"
	"pizdec/internal/node"
	"pizdec/internal/settings"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{}

func GenerateProfile(profile *ipc.UserProfile) {
	rsaPrivate, rsaPublic := algorithms.RSA_GenerateKeys(16384)
	ecdsaPrivate, ecdsaPublic := algorithms.ECDSA_GenerateKeys()

	userID := bytes.Join([][]byte{rsaPublic[12:24], ecdsaPublic[12:24]}, nil)

	profile.EncryptionPublicKey = rsaPublic
	profile.SignaturePublicKey = ecdsaPublic
	profile.EncryptionPrivateKey = rsaPrivate
	profile.SignaturePrivateKey = ecdsaPrivate
	profile.UserID = userID
}

func main() {
	/**
	Basic implementation
	*/

	//GenerateProfile(&profile_)

	//settings.SaveSettings(settings_, "./config/config.json")
	profile_, err := settings.LoadSettings("./config/config.json")

	if err != nil {
		return
	}

	fmt.Printf("profile_.UserID: %v\n", hex.EncodeToString(profile_.Profile.UserID))
	fmt.Printf("profile_.Profile.EncryptionPrivateKey: %v\n", hex.EncodeToString(profile_.Profile.EncryptionPrivateKey))
	fmt.Printf("profile_.Profile.SignaturePrivateKey: %v\n", hex.EncodeToString(profile_.Profile.SignaturePrivateKey))
	fmt.Printf("profile_.Profile.EncryptionPublicKey: %v\n", hex.EncodeToString(profile_.Profile.EncryptionPublicKey))
	fmt.Printf("profile_.Profile.SignaturePublicKey: %v\n", hex.EncodeToString(profile_.Profile.SignaturePublicKey))

	//settings.LoadSettings("./config/config.json")

	node.StartNode()
}
