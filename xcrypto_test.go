package fileutil

import (
	"testing"
	"strings"
)

// tests that a string is correctly encrypted/decrypted (when having appropriate lenghts and non-empty)
func TestEncryptDecrypt(t *testing.T) {
	key := []byte("X5B1s#ryFvr1rysXv@%6!@#Axq&sr19Z") // 32 chars = 8 x 32 = 256 bit key
	text := []byte("If to do were as easy as to know what were good to do, chapels had been churches, and poor men's cottage princes palaces.")

	encrypted, err := Encrypt(key, text)

	if err != nil {
		t.Error("Error while encrypting text")
	}

	if len(encrypted) == 0 {
		t.Error("Encrypted text is empty")
	}

	decrypted, err := Decrypt(key, encrypted)

	if err != nil {
		t.Error("Error while decrypting text")
	}

	if len(decrypted) == 0 {
		t.Error("Decrypted text is empty")
	}

	if strings.Compare(string(decrypted), string(text)) != 0 {
		t.Error("Decrypted text is not equal to original text")
	}
}
