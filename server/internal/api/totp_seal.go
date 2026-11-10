package api

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"strconv"
)

// sealTOTP seals a secret under the server's TOTP key. The account id is
// bound in, so a sealed secret cannot be moved to another account; a copy
// of the database alone does not hold the secrets.
func (a *accounts) sealTOTP(userID int64, secret []byte) []byte {
	gcm := a.totpCipher()
	nonce := randomBytes(gcm.NonceSize())
	return gcm.Seal(nonce, nonce, secret, totpAAD(userID))
}

func (a *accounts) openTOTP(userID int64, sealed []byte) ([]byte, error) {
	gcm := a.totpCipher()
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("sealed TOTP secret too short")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], totpAAD(userID))
}

func (a *accounts) totpCipher() cipher.AEAD {
	block, err := aes.NewCipher(a.keys.totp)
	if err != nil {
		panic(err) // the key is always 32 bytes
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm
}

func totpAAD(userID int64) []byte {
	return []byte("vault-share/totp/" + strconv.FormatInt(userID, 10))
}
