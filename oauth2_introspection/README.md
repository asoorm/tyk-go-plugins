# OAuth2.0 Introspection Plugin for Tyk Gateway

This plugin allows the Tyk Gateway to perform an OAuth2.0 Introspection request
 to a 3rd party authorization server in order to validate an access token which may be a JWT or opaque.
 
The plugin aims for compliance with [RFC7662: OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662).

## Configuration

Configuration is via environment variables.

```.env
OAUTH2_INTROSPECT_ENDPOINT="https://SOME_AUTHORIZATION_SERVER_INTROSPECTION_ENDPOINT"
OAUTH2_INTROSPECT_AUTHORIZATION="AUTHORIZATION_HEADER_VALUE"
```

Basic Auth Example

```text
OAUTH2_INTROSPECT_AUTHORIZATION="Bearer 23410913-abewfq.123483"

     POST /introspect HTTP/1.1
     Host: server.example.com
     Accept: application/json
     Content-Type: application/x-www-form-urlencoded
     Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

     token=2YotnFZFEjr1zCsicMWpAA
```

Bearer token example

```text
OAUTH2_INTROSPECT_AUTHORIZATION="Bearer 23410913-abewfq.123483"

     POST /introspect HTTP/1.1
     Host: server.example.com
     Accept: application/json
     Content-Type: application/x-www-form-urlencoded
     Authorization: Bearer 23410913-abewfq.123483

     token=2YotnFZFEjr1zCsicMWpAA
```

## Usage

Assuming JWT authentication is enabled, Tyk can Authenticate using the access_token (sounds weird I know).

Ensure that the API definition does not strip the access_token, and configure this plugin in the `post_key_auth` hook.

```json
{
  "custom_middleware": {
    "post_key_auth": [{
      "name": "OAuth2Introspect",
      "path": "SOMEDIRECTORY/oauth2_introspection/oauth2_introspection.so"
    }],
  "driver": "goplugin",
}
```

This plugin will then strip the token to ensure that it doesn't leak upstream.

If there are any scopes present in the access token, they will be inserted into the request context for use later in the 
middleware chain.

## TODO / Current Limitations

- [ ] Build internal configurable cache to not spam the introspection endpoint.
- [ ] Hardcoded to only introspect the `access_token`.
- [ ] Hardcoded to only look in the `authorization` header for the `access_token`