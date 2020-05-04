package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/square/go-jose"
)

type testStruct struct {
	In  []byte
	Out jsonWebKeys
}

var test = testStruct{
	In: []byte(`{
  "keys": [
    {
      "kid": "L_OIax5OnVSaZL0Rkikdo6_4z7CttymiBxGhdizUQP0",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "tQDpW46x1Zjnwrqu-PcpPPxPTxVYryRwNbpkSbkC1i46mmvhI-zHfCSd2fdAhsqNX6XtzUNF10vOd0rR1U8jNxPMXYV_kHD7pOdJsc2kdDS6uRT9AIg9WHe0AoK2HraPEyAnVgq5TWVxx0IT4YGDXupOniAHNPcZ0dPNlxV5VdD8lsKXBOs6HWA93UqwxF6pYiEthxzE4kPZQaB6s6qQ5RGs47wYISyw-cUdDHp5VH_wJIr4Y9Vi8S-vEsKC9_XqQwvqMBQ96WRMDReoreUEsXPR3AX7_yE7h7UgHFV_qSNyLGFoNTTwioc7A5-S6OEuxc7MGZp-XBWsVuMEuXg0vQ",
      "e": "AQAB"
    }
  ]
}`),
	Out: jsonWebKeys{
		Keys: []jwksTmpl{
			{
				Kid: "L_OIax5OnVSaZL0Rkikdo6_4z7CttymiBxGhdizUQP0",
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
				N:   "tQDpW46x1Zjnwrqu-PcpPPxPTxVYryRwNbpkSbkC1i46mmvhI-zHfCSd2fdAhsqNX6XtzUNF10vOd0rR1U8jNxPMXYV_kHD7pOdJsc2kdDS6uRT9AIg9WHe0AoK2HraPEyAnVgq5TWVxx0IT4YGDXupOniAHNPcZ0dPNlxV5VdD8lsKXBOs6HWA93UqwxF6pYiEthxzE4kPZQaB6s6qQ5RGs47wYISyw-cUdDHp5VH_wJIr4Y9Vi8S-vEsKC9_XqQwvqMBQ96WRMDReoreUEsXPR3AX7_yE7h7UgHFV_qSNyLGFoNTTwioc7A5-S6OEuxc7MGZp-XBWsVuMEuXg0vQ",
				E:   "AQAB",
				X5C: []string{
					"MIIBCgKCAQEAtQDpW46x1Zjnwrqu+PcpPPxPTxVYryRwNbpkSbkC1i46mmvhI+zHfCSd2fdAhsqNX6XtzUNF10vOd0rR1U8jNxPMXYV/kHD7pOdJsc2kdDS6uRT9AIg9WHe0AoK2HraPEyAnVgq5TWVxx0IT4YGDXupOniAHNPcZ0dPNlxV5VdD8lsKXBOs6HWA93UqwxF6pYiEthxzE4kPZQaB6s6qQ5RGs47wYISyw+cUdDHp5VH/wJIr4Y9Vi8S+vEsKC9/XqQwvqMBQ96WRMDReoreUEsXPR3AX7/yE7h7UgHFV/qSNyLGFoNTTwioc7A5+S6OEuxc7MGZp+XBWsVuMEuXg0vQIDAQAB",
				},
			},
		},
	},
}

func TestTranslateJWKSet(t *testing.T) {

	t1 := &jose.JSONWebKeySet{}
	json.Unmarshal(test.In, t1)

	translated := TranslateJWKSet(t1)

	if !cmp.Equal(test.Out.Keys[0], translated[0]) {
		t.Log("test.Out != translated[0]")

		testOutBytes, _ := json.Marshal(test.Out.Keys[0])
		newJwksBytes, _ := json.Marshal(translated[0])

		t.Log("exp: ", string(testOutBytes))
		t.Log("got: ", string(newJwksBytes))

		t.Fail()
	}
}

func TestUnmarshalMarshal(t *testing.T) {
	jsonWebKeySet := &jose.JSONWebKeySet{}

	if err := json.Unmarshal(test.In, jsonWebKeySet); err != nil {
		t.Logf("failed unmarshalling JWKS: %s", err.Error())
		t.FailNow()
	}

	newJwks := jsonWebKeys{}
	for _, v := range jsonWebKeySet.Keys {
		switch key := v.Key.(type) {
		case *rsa.PublicKey:
			x509Bytes := x509.MarshalPKCS1PublicKey(key)

			// make a big enough byte slice
			e := make([]byte, 8)
			// fill it
			binary.BigEndian.PutUint64(e, uint64(key.E))
			// trim buffer of null values
			e = bytes.TrimLeft(e, "\x00")

			newJwks.Keys = append(newJwks.Keys, jwksTmpl{
				Kid: v.KeyID,
				Kty: "RSA",
				Alg: v.Algorithm,
				Use: v.Use,
				N:   strings.TrimRight(base64.URLEncoding.EncodeToString(key.N.Bytes()), "="),
				E:   strings.TrimRight(base64.URLEncoding.EncodeToString(e), "="),
				X5C: []string{strings.TrimRight(base64.StdEncoding.EncodeToString(x509Bytes), "=")},
			})
		}

		testOutBytes, _ := json.Marshal(test.Out)
		newJwksBytes, _ := json.Marshal(newJwks)

		t.Log("exp: ", string(testOutBytes))
		t.Log("got: ", string(newJwksBytes))

		if !cmp.Equal(test.Out, newJwks) {
			t.Log("test.Out != newJwks")
			t.Fail()
		}
	}
}
