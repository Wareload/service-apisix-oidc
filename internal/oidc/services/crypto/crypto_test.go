package crypto

import (
	"crypto/rand"
	"strings"
	"testing"
)

const testString = "This is a very long test string including some symbols like !\"§$%&/()=?"

func TestEncryption(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := EncryptAES([]byte(testString), key)
	decrypted, err := DecryptAES(encrypted, key)
	if err != nil || strings.Compare(testString, string(decrypted)) != 0 {
		t.Fatal()
	}
}

func TestEncryptionWithKey(t *testing.T) {
	keyString := "mysecurefixedkey1234567890123456" // 32 characters
	key := []byte(keyString)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := EncryptAES([]byte(testString), key)
	decrypted, err := DecryptAES(encrypted, key)
	if err != nil || strings.Compare(testString, string(decrypted)) != 0 {
		t.Fatal()
	}
}
