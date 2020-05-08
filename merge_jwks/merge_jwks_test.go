package main

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/square/go-jose"
)

type testStruct struct {
	In  []byte
	Out jwksUriResponse
}

var testcases = []testStruct{
	{
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
		Out: jwksUriResponse{
			Keys: []jwksTmpl{
				{
					Kid: "L_OIax5OnVSaZL0Rkikdo6_4z7CttymiBxGhdizUQP0",
					Kty: "RSA",
					Alg: "RS256",
					Use: "sig",
					N:   "tQDpW46x1Zjnwrqu-PcpPPxPTxVYryRwNbpkSbkC1i46mmvhI-zHfCSd2fdAhsqNX6XtzUNF10vOd0rR1U8jNxPMXYV_kHD7pOdJsc2kdDS6uRT9AIg9WHe0AoK2HraPEyAnVgq5TWVxx0IT4YGDXupOniAHNPcZ0dPNlxV5VdD8lsKXBOs6HWA93UqwxF6pYiEthxzE4kPZQaB6s6qQ5RGs47wYISyw-cUdDHp5VH_wJIr4Y9Vi8S-vEsKC9_XqQwvqMBQ96WRMDReoreUEsXPR3AX7_yE7h7UgHFV_qSNyLGFoNTTwioc7A5-S6OEuxc7MGZp-XBWsVuMEuXg0vQ",
					E:   "AQAB",
					X5C: []string{
						"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQDpW46x1Zjnwrqu+PcpPPxPTxVYryRwNbpkSbkC1i46mmvhI+zHfCSd2fdAhsqNX6XtzUNF10vOd0rR1U8jNxPMXYV/kHD7pOdJsc2kdDS6uRT9AIg9WHe0AoK2HraPEyAnVgq5TWVxx0IT4YGDXupOniAHNPcZ0dPNlxV5VdD8lsKXBOs6HWA93UqwxF6pYiEthxzE4kPZQaB6s6qQ5RGs47wYISyw+cUdDHp5VH/wJIr4Y9Vi8S+vEsKC9/XqQwvqMBQ96WRMDReoreUEsXPR3AX7/yE7h7UgHFV/qSNyLGFoNTTwioc7A5+S6OEuxc7MGZp+XBWsVuMEuXg0vQIDAQAB",
					},
				},
			},
		},
	},
	{
		In: []byte(`{
  "keys": [
    {
      "kid": "L_OIax5OnVSaZL0Rkikdo6_4z7CttymiBxGhdizUQP0",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "tQDpW46x1Zjnwrqu-PcpPPxPTxVYryRwNbpkSbkC1i46mmvhI-zHfCSd2fdAhsqNX6XtzUNF10vOd0rR1U8jNxPMXYV_kHD7pOdJsc2kdDS6uRT9AIg9WHe0AoK2HraPEyAnVgq5TWVxx0IT4YGDXupOniAHNPcZ0dPNlxV5VdD8lsKXBOs6HWA93UqwxF6pYiEthxzE4kPZQaB6s6qQ5RGs47wYISyw-cUdDHp5VH_wJIr4Y9Vi8S-vEsKC9_XqQwvqMBQ96WRMDReoreUEsXPR3AX7_yE7h7UgHFV_qSNyLGFoNTTwioc7A5-S6OEuxc7MGZp-XBWsVuMEuXg0vQ",
      "e": "AQAB",
      "x5c": [
        "MIICnzCCAYcCBgFxnYapWjANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhsZWFybmluZzAeFw0yMDA0MjExNjE0NDBaFw0zMDA0MjExNjE2MjBaMBMxETAPBgNVBAMMCGxlYXJuaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQDpW46x1Zjnwrqu+PcpPPxPTxVYryRwNbpkSbkC1i46mmvhI+zHfCSd2fdAhsqNX6XtzUNF10vOd0rR1U8jNxPMXYV/kHD7pOdJsc2kdDS6uRT9AIg9WHe0AoK2HraPEyAnVgq5TWVxx0IT4YGDXupOniAHNPcZ0dPNlxV5VdD8lsKXBOs6HWA93UqwxF6pYiEthxzE4kPZQaB6s6qQ5RGs47wYISyw+cUdDHp5VH/wJIr4Y9Vi8S+vEsKC9/XqQwvqMBQ96WRMDReoreUEsXPR3AX7/yE7h7UgHFV/qSNyLGFoNTTwioc7A5+S6OEuxc7MGZp+XBWsVuMEuXg0vQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQABl4C4P8qea97z3F6Y0XCYU0ka4saDkWEK9Kymjknsk/2/IkGPIwd8+qAB+XNJoye8oZC4Fdm115N/RPQbUh+Sm2AnGEkfzmI7laxYrFhYAqiHUlw3TuWue1vWK/JNFpuhOtYUNbNa/vC/afumImxHRIEEn34eJPcP3lwBqobwqr6qKm0I5SZr2HAWY2mU+pRgTYT7TfItx3VSe28qHX6qpm6UIBbeFLyt4JcmSIXSa7kyB7ZsFT2jwImdh186JqA2Fbu4zqLUyu6pGASuTTl3cUclujaguJfAgJ9ju5SumPxILXSZJ7nm44w+RoEdWrc7P7akhshCe92yKj+1Y36M"
      ],
      "x5t": "U0YPpRj6ASeibAID-z1nNZYd1Is",
      "x5t#S256": "IKkqT3FX6gy4o8VUPj0Lx0SC7BL5xGOxSxJezChLYYo"
    }
  ]
}`),
		Out: jwksUriResponse{
			Keys: []jwksTmpl{
				{
					Kid: "L_OIax5OnVSaZL0Rkikdo6_4z7CttymiBxGhdizUQP0",
					Kty: "RSA",
					Alg: "RS256",
					Use: "sig",
					N:   "tQDpW46x1Zjnwrqu-PcpPPxPTxVYryRwNbpkSbkC1i46mmvhI-zHfCSd2fdAhsqNX6XtzUNF10vOd0rR1U8jNxPMXYV_kHD7pOdJsc2kdDS6uRT9AIg9WHe0AoK2HraPEyAnVgq5TWVxx0IT4YGDXupOniAHNPcZ0dPNlxV5VdD8lsKXBOs6HWA93UqwxF6pYiEthxzE4kPZQaB6s6qQ5RGs47wYISyw-cUdDHp5VH_wJIr4Y9Vi8S-vEsKC9_XqQwvqMBQ96WRMDReoreUEsXPR3AX7_yE7h7UgHFV_qSNyLGFoNTTwioc7A5-S6OEuxc7MGZp-XBWsVuMEuXg0vQ",
					E:   "AQAB",
					X5C: []string{
						"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQDpW46x1Zjnwrqu+PcpPPxPTxVYryRwNbpkSbkC1i46mmvhI+zHfCSd2fdAhsqNX6XtzUNF10vOd0rR1U8jNxPMXYV/kHD7pOdJsc2kdDS6uRT9AIg9WHe0AoK2HraPEyAnVgq5TWVxx0IT4YGDXupOniAHNPcZ0dPNlxV5VdD8lsKXBOs6HWA93UqwxF6pYiEthxzE4kPZQaB6s6qQ5RGs47wYISyw+cUdDHp5VH/wJIr4Y9Vi8S+vEsKC9/XqQwvqMBQ96WRMDReoreUEsXPR3AX7/yE7h7UgHFV/qSNyLGFoNTTwioc7A5+S6OEuxc7MGZp+XBWsVuMEuXg0vQIDAQAB",
					},
				},
			},
		},
	},
	{
		In: []byte(`{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "kid": "V1y7y0M7B6rdA0MXWgPj6bYEb3Md2mXULcU_IvL2URM",
      "use": "sig",
      "e": "AQAB",
      "n": "nZPtrhV6ernRxuPI-Sz6kdFRXJR0CFx03UmBHzh0gDpwYsudnY-0AIxxVYAf3kDAhS9qhjVsVio-W7A3IXPlCmuQfDGmpc5vlUfIPgTAuAxt9zY3udk8dNdWY68YzFGSLpuQfCV8uIpwJJxapNjJn5VkVEEh2-b0t-JDPqcO023-0y-mxp4v7UV5Ddv-YfOtxbAKYlKwiConORpuQD-g-is_FZynm4mxSKbb59MKtwIfcjxllDafwNOq4g3TZBXTnqM42I-RpEwyIV5TGaZ2jEJVm9VpXQEgUW2wPDIPfyY1Ie3FrRfMSzTL8efhW74Wa6wPj2njPUqT6-16v0XBBQ"
    }
  ]
}`),
		Out: jwksUriResponse{
			Keys: []jwksTmpl{
				{
					Kid: "V1y7y0M7B6rdA0MXWgPj6bYEb3Md2mXULcU_IvL2URM",
					Kty: "RSA",
					Alg: "RS256",
					Use: "sig",
					N:   "nZPtrhV6ernRxuPI-Sz6kdFRXJR0CFx03UmBHzh0gDpwYsudnY-0AIxxVYAf3kDAhS9qhjVsVio-W7A3IXPlCmuQfDGmpc5vlUfIPgTAuAxt9zY3udk8dNdWY68YzFGSLpuQfCV8uIpwJJxapNjJn5VkVEEh2-b0t-JDPqcO023-0y-mxp4v7UV5Ddv-YfOtxbAKYlKwiConORpuQD-g-is_FZynm4mxSKbb59MKtwIfcjxllDafwNOq4g3TZBXTnqM42I-RpEwyIV5TGaZ2jEJVm9VpXQEgUW2wPDIPfyY1Ie3FrRfMSzTL8efhW74Wa6wPj2njPUqT6-16v0XBBQ",
					E:   "AQAB",
					X5C: []string{
						"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnZPtrhV6ernRxuPI+Sz6kdFRXJR0CFx03UmBHzh0gDpwYsudnY+0AIxxVYAf3kDAhS9qhjVsVio+W7A3IXPlCmuQfDGmpc5vlUfIPgTAuAxt9zY3udk8dNdWY68YzFGSLpuQfCV8uIpwJJxapNjJn5VkVEEh2+b0t+JDPqcO023+0y+mxp4v7UV5Ddv+YfOtxbAKYlKwiConORpuQD+g+is/FZynm4mxSKbb59MKtwIfcjxllDafwNOq4g3TZBXTnqM42I+RpEwyIV5TGaZ2jEJVm9VpXQEgUW2wPDIPfyY1Ie3FrRfMSzTL8efhW74Wa6wPj2njPUqT6+16v0XBBQIDAQAB",
					},
				},
			},
		},
	},
}

func TestTranslateJWKSet(t *testing.T) {

	for i, tt := range testcases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t1 := &jose.JSONWebKeySet{}
			json.Unmarshal(tt.In, t1)

			translated, err := TranslateJWKSet(t1)
			if err != nil {
				t.Log("error", err.Error())
				t.FailNow()
			}

			if !cmp.Equal(tt.Out.Keys[0], translated[0]) {
				t.Log("test.Out != translated[0]")

				testOutBytes, _ := json.Marshal(tt.Out.Keys[0])
				newJwksBytes, _ := json.Marshal(translated[0])

				t.Log("exp: ", string(testOutBytes))
				t.Log("got: ", string(newJwksBytes))

				t.FailNow()
			}
		})
	}
}
