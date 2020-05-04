# Merge multiple jwks_uri's

> This microservice is experimental & subject to breaking changes

## Motivation

- merge the public certificates of multiple identity providers?
- create x5c certificates from n (modulus) & e (exponent) from JWK if not supplied by the IdP

## Usage

- Modify the config.yaml for your use-case
- Run the microservice

## Todo

- Publish to dockerhub to make it easier to run in a dockerized environment

[6.3.1.1. "n" (modulus) parameter](https://tools.ietf.org/html/rfc7518#section-6.3.1.1)
```text
The "n" (modulus) parameter contains the modulus value for the RSA
public key.  It is represented as a Base64urlUInt-encoded value.

Note that implementers have found that some cryptographic libraries
prefix an extra zero-valued octet to the modulus representations they
return, for instance, returning 257 octets for a 2048-bit key, rather
than 256.  Implementations using such libraries will need to take
care to omit the extra octet from the base64url-encoded
representation.
```

[6.3.1.2.  "e" (Exponent) Parameter](https://tools.ietf.org/html/rfc7518#section-6.3.1.2)
```text
The "e" (exponent) parameter contains the exponent value for the RSA
public key.  It is represented as a Base64urlUInt-encoded value.

For instance, when representing the value 65537, the octet sequence
to be base64url-encoded MUST consist of the three octets [1, 0, 1];
the resulting representation for this value is "AQAB".
```
