package dataprovider

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// hashSecret generates a cryptographic hash (using bcrypt) of a plain secret.
func hashSecret(secret string) (bcryptHash string, err error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(secret), 10)
	return string(bytes), err
}

// checkSecretHash validates that the secret matches the hash (using bcrypt).
func checkSecretHash(secret, bcryptHash string) (isMatch bool) {
	err := bcrypt.CompareHashAndPassword([]byte(bcryptHash), []byte(secret))
	return err == nil
}

// generateIdFromSecret will generate a small ID (6 chars) based on the secret.
// this is NOT used to prove the client has the correct passphrase,
// it is only used to identify the client, otherwise the we would need to provide
// a client both a passphrase and a user (two things to remember instead of one).
// This also means that two clients cannot have the same passphrase. However, since
// only the admin can create new clients, then only the admin would be aware of this.
// we cannot use bcrypt here because value would change every time we hash it,
// instead we return the first 6 chars from a SHA256 sum of the secret.
func generateIdFromSecret(secret string) (id string) {
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(secret)))
	return sum[0:6]
}
