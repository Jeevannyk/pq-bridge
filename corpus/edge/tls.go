package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
)

func ServerKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func LegacyKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 3072)
}

func Config() *tls.Config {
	fmt.Println("rsa keys rotated")
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}
}
