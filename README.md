Alternative JWT auth provider for vertx

- Just java
- Only authenticates JWT tokens. Doesn't create them (at the moment we have a different internal project that does this)


  # ignoreExpiration = false
  # allowedClockSkewInSeconds = 30
  # requireSubject = true
  # requireJwtId = true
  issuer = name
  audience = audience

  # https://tools.ietf.org/html/draft-ietf-jose-json-web-key-40#section-5
  jwks {
    keys: [{"kty":"RSA","kid":"myid1","n":"","e":""}]
  }

I generated the key by running example code from Jose4J. The above JSON syntax is the default output from jose4j.