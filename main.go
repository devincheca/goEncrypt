package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

type input struct {
	Key, Message string
}

func initEncrypt(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	var fromReq input
	err = json.Unmarshal(body, &fromReq)
	if err != nil {
		panic(err)
	}
	if fromReq.Key == "" {
		fmt.Print(w, "Request received without valid key.")
		fmt.Fprint(w, "A key is required for encryption.")
		panic("A key is required for encryption.")
	}
	if fromReq.Message == "" {
		fmt.Print(w, "Request received with valid key and without message")
		fmt.Fprint(w, "A message is required for encryption.")
		panic("A message is required for encryption.")
	}
	eMessage, nonce := encrypt(fromReq.Key, fromReq.Message)
	encryptMessage := fmt.Sprintf("%x", eMessage)
	nonceString := fmt.Sprintf("%x", nonce)
	fmt.Print("{\"EncryptedMessage\":\"", encryptMessage, "\",")
	fmt.Print("\"Nonce\":\"", nonceString, "\"}")
	fmt.Fprint(w, "{\"EncryptedMessage\":\"", encryptMessage, "\",")
	fmt.Fprint(w, "\"Nonce\":\"", nonceString, "\"}")
}

func main() {
	http.HandleFunc("/", initEncrypt)
	fmt.Println("listening on port 3000...")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		log.Fatal(err)
	}
}

func encrypt(reqKey, reqMessage string) ([]byte, []byte) {
	// When decoded the key should be 16 bytes (AES-128)// or 32 (AES-256).
	key, _ := hex.DecodeString(reqKey)
	plaintext := []byte(reqMessage)
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Key needs to be 16 bytes (AES-128) compliant")
		panic(err.Error())
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	//fmt.Printf("%x\n", ciphertext)
	return ciphertext, nonce
}
