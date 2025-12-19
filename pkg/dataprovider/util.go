package dataprovider

import (
	"golang.org/x/crypto/bcrypt"
)

// hashSecret generates a cryptographic hash (using bcrypt) of a plain secret.
func hashSecret(secret string) (bcryptHash string, err error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(secret), 10)
	return string(bytes), err
}

// VerifySecret compares a plain text secret against a bcrypt hash.
// Returns nil if the secret matches, or an error if it doesn't.
func VerifySecret(hashedSecret, plainSecret string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedSecret), []byte(plainSecret))
}
