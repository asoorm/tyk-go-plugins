# Merge multiple JSON Web Key Sets

> This microservice is still a little experimental & subject to breaking changes

## Goals & Motivations

Make it easier to validate JWT tokens with multiple issuers.

The merge_jwks microservice will pull in, merge and normalise the JWKS from your configured
JWKS URIs, and expose it's own JWKS_URI.

You can now easily call the `/certs` endpoint and use this as your new JWKS uri whenever you
need to validate an access token.

### Why JWKS?

Suppose you receive an access token with a request, and you need to verify it's authenticity.
The typical flow would be that you have a public certificate of a whitelisted Identity Provider
and then you validate the signature of the JWT using that public certificate.

All is good!

But now, the Identity Provider rotates it's certificates - which is completely reasonable.
You now need to somehow identify that this happened, and load the latest public certificate.
Clearly this is a bit clunky, and not best-practice.

JWKS to the rescue!

Identity providers expose a public JWKS_URI, which publishes it's public certificates,
alongside a key id (KID) to help identify the certificate that it was signed with.

As such, if you know the identity provider's JWKS_URI, then you can read the KID claim
in the header of the JWT, and lookup that KID claim in the response from the JWKS_URI.

From here, you always get a fresh and up-to-date copy of the public key, and the Identity
Provider can rotate their certificates to their heart's content. Boom!

# Merging JSON Web Key Sets

Oops, now we have a problem...

In more complex setups, it's completely normal to have more than one Identity Provider
issuing access tokens.

e.g. Different social providers, or Okta for public clients, but Ping or Keycloak or
some Active Directory service for internal clients. Maybe you are migrating Identity Providers
and you need to support both for a while.

Now, our app we needs to know about 2 Idenetity provider endpoints. And based on the JWT
issuer claim, be able to guess, or discover which identity provider's JWKS_URI to query
in order to pull the public key, and validate the access token.

### Standardise the response output

RFC7517 specifies that the use of the x5c parameter is optional within a JSON Web Key (JWK). 
Despite being extremely useful for pretty much every service that uses certificates, some IdPs
seem to be a bit MVP / Purist or just Lazy in terms of what they implement.

As such, when looking up a KID to find the public certificate from the jwks_uri as specified in
the OIDC discovery endpoint, it may be necessary to convert the (n) modulus & (e) exponent to an
x5c certificate if not presented.

https://tools.ietf.org/html/rfc7517#section-4.7

## Usage

- Modify the config.yaml for your use-case

```
# address you want the service to listen on
address: ":9000"

# the jwks path endpoint you wish to expose
jwks_uri: "/certs"

merge:
  - "https://{oktaorg}.okta.com/oauth2/default/v1/keys"
  - "https://{keycloak}/auth/realms/{realm}/protocol/openid-connect/certs"
```

- Run the microservice

```
docker pull mangomm/merge-jwks:0.6
merge_jwks % docker run -it -p 9000:9000 -v $(pwd)/config.yaml:/opt/merge_jwks/config.yaml mangomm/merge-jwks:0.6 
Build information:
        commit: a00870ce4f3680b34ac2b42dffb1e84a1edfa2c1
        tag: merge-jwks-0.6
starting server on: :9000
```

- Test it out

```
{
  "keys": [
    {
      "kid": "V1y7y0M7B6rdA0MXWgPj6bYEb3Md2mXULcU_IvL2URM",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "nZPtrhV6ernRxuPI-Sz6kdFRXJR0CFx03UmBHzh0gDpwYsudnY-0AIxxVYAf3kDAhS9qhjVsVio-W7A3IXPlCmuQfDGmpc5vlUfIPgTAuAxt9zY3udk8dNdWY68YzFGSLpuQfCV8uIpwJJxapNjJn5VkVEEh2-b0t-JDPqcO023-0y-mxp4v7UV5Ddv-YfOtxbAKYlKwiConORpuQD-g-is_FZynm4mxSKbb59MKtwIfcjxllDafwNOq4g3TZBXTnqM42I-RpEwyIV5TGaZ2jEJVm9VpXQEgUW2wPDIPfyY1Ie3FrRfMSzTL8efhW74Wa6wPj2njPUqT6-16v0XBBQ",
      "e": "AQAB",
      "x5c": [
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnZPtrhV6ernRxuPI+Sz6kdFRXJR0CFx03UmBHzh0gDpwYsudnY+0AIxxVYAf3kDAhS9qhjVsVio+W7A3IXPlCmuQfDGmpc5vlUfIPgTAuAxt9zY3udk8dNdWY68YzFGSLpuQfCV8uIpwJJxapNjJn5VkVEEh2+b0t+JDPqcO023+0y+mxp4v7UV5Ddv+YfOtxbAKYlKwiConORpuQD+g+is/FZynm4mxSKbb59MKtwIfcjxllDafwNOq4g3TZBXTnqM42I+RpEwyIV5TGaZ2jEJVm9VpXQEgUW2wPDIPfyY1Ie3FrRfMSzTL8efhW74Wa6wPj2njPUqT6+16v0XBBQIDAQAB"
      ]
    },
    {
      "kid": "L_OIax5OnVSaZL0Rkikdo6_4z7CttymiBxGhdizUQP0",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "tQDpW46x1Zjnwrqu-PcpPPxPTxVYryRwNbpkSbkC1i46mmvhI-zHfCSd2fdAhsqNX6XtzUNF10vOd0rR1U8jNxPMXYV_kHD7pOdJsc2kdDS6uRT9AIg9WHe0AoK2HraPEyAnVgq5TWVxx0IT4YGDXupOniAHNPcZ0dPNlxV5VdD8lsKXBOs6HWA93UqwxF6pYiEthxzE4kPZQaB6s6qQ5RGs47wYISyw-cUdDHp5VH_wJIr4Y9Vi8S-vEsKC9_XqQwvqMBQ96WRMDReoreUEsXPR3AX7_yE7h7UgHFV_qSNyLGFoNTTwioc7A5-S6OEuxc7MGZp-XBWsVuMEuXg0vQ",
      "e": "AQAB",
      "x5c": [
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQDpW46x1Zjnwrqu+PcpPPxPTxVYryRwNbpkSbkC1i46mmvhI+zHfCSd2fdAhsqNX6XtzUNF10vOd0rR1U8jNxPMXYV/kHD7pOdJsc2kdDS6uRT9AIg9WHe0AoK2HraPEyAnVgq5TWVxx0IT4YGDXupOniAHNPcZ0dPNlxV5VdD8lsKXBOs6HWA93UqwxF6pYiEthxzE4kPZQaB6s6qQ5RGs47wYISyw+cUdDHp5VH/wJIr4Y9Vi8S+vEsKC9/XqQwvqMBQ96WRMDReoreUEsXPR3AX7/yE7h7UgHFV/qSNyLGFoNTTwioc7A5+S6OEuxc7MGZp+XBWsVuMEuXg0vQIDAQAB"
      ]
    }
  ]
}
```
