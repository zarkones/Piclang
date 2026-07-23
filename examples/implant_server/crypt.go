package main

import (
	"crypto/rc4"
	"encoding/base64"
	"fmt"
)

// seal: Base64(RC4(key, plain)) - matches implant c2.Seal.
func seal(plain, key []byte) (string, error) {
	if len(key) == 0 {
		return "", fmt.Errorf("empty key")
	}
	buf := make([]byte, len(plain))
	copy(buf, plain)
	c, err := rc4.NewCipher(key)
	if err != nil {
		return "", err
	}
	c.XORKeyStream(buf, buf)
	return base64.StdEncoding.EncodeToString(buf), nil
}

// open: RC4(key, Base64Decode(b64)) - matches implant c2.Open.
func open(b64 string, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("empty key")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.XORKeyStream(raw, raw)
	return raw, nil
}
