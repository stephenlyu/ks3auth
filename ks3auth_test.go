package ks3auth

import (
	"fmt"
	"testing"
)

func TestCalcSignature(t *testing.T) {
	sk := "sk"
	bucket := "test"
	key := "信道配置使用.pdf"
	resource := "?uploads"
	httpVerb := "POST"
	headers := map[string]string{"x-kss-server-side-encryption": "AES256", "x-kss-date": "Sat, 17 Feb 2024 07:30:04 GMT"}
	timestamp := "Sat, 17 Feb 2024 07:30:04 GMT"

	signature := CalcSignature(sk, bucket, key, resource, httpVerb, headers, timestamp)
	fmt.Printf("signature: %s\n", signature)
	if signature != "4l7X5hO0Da/iOKNRSiDBO5+TnZ8=" {
		t.Errorf("bad signature")
	}
}
