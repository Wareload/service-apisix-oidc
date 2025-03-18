package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func EncryptAES(plainText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// PKCS7 pad the plaintext
	plainText = pkcs7Pad(plainText, aes.BlockSize)
	// IV (Initialization Vector) must be random and unique for each encryption
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	// Create a new AES CBC cipher mode
	cipherText := make([]byte, len(plainText))
	stream := cipher.NewCBCEncrypter(block, iv)
	stream.CryptBlocks(cipherText, plainText)
	// Append the IV to the beginning of the cipherText
	return append(iv, cipherText...), nil
}

func DecryptAES(cipherText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(cipherText) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	// Extract the IV from the beginning of the ciphertext
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	// Create a new AES CBC cipher mode
	stream := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(cipherText))
	stream.CryptBlocks(plainText, cipherText)
	// Remove padding
	return pkcs7Unpad(plainText)
}

// PKCS7 padding
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// Remove padding after decryption
func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("data length is zero")
	}
	padding := int(data[length-1])
	if padding > length {
		return nil, fmt.Errorf("padding size is larger than data length")
	}
	return data[:length-padding], nil
}
