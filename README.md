# chainjwt

[![GoDoc](https://godoc.org/github.com/ScaleFT/chainjwt?status.svg)](https://godoc.org/github.com/ScaleFT/chainjwt)
[![Build Status](https://travis-ci.org/ScaleFT/chainjwt.svg?branch=master)](https://travis-ci.org/ScaleFT/chainjwt)


`chainjwt` is a Go library for validating a JWT based on a trust assertion from another JWT.

This structure allows for:

- Private Key storage on clients in enclaves or other secure methods.
- Validation by a Services with limited need for remote queries.
- Eliminating long lived bearer tokens, since a client can mint a new request signed JWT for each request.

[RFC 7517 provides the x5c and x5t parameters](https://tools.ietf.org/html/rfc7517#section-4.7), which could be used for a similiar purpose using X.509 Certificate Authorities. `chainjwt` avoids the surface area of X.509 certificate chain verification by using a single-length chain of JWTs as the assertion method.


`chainjwt` depends upon [Square's go-jose.v2](https://godoc.org/gopkg.in/square/go-jose.v2) and [ScaleFT's xjwt](https://godoc.org/github.com/ScaleFT/xjwt) libraries for the heavy lifting of parsing and validating JWTs.

## Details

The JWT to be verified is called the 'outer JWT'.

`chainjwt` adds a `jwc` field to the header of the outer JWT.  The `jwc` header field contains a compact-form JWT (the 'inner JWT') that is trusted by the verifying party (similar to an X.509 Certificate Authority).

To validate a JWT, the `jwc` header field is first extracted, parsed, and verified from the outer JWT's header.  The `tjwk` claim in the inner JWT is a JWK Public Key that the verifing code uses to validate the whole outer JWT.  The `tjwk` claim could be thought of as a client certificate in an X.509 system.

The signature on the outer JWT is evidence of ownership of the associated private key referenced by the public key in the `tjwk` claim.

### Example JWC Header

In the header of the 'outer JWT':

```
{
  "alg": "EdDSA",
  "jwc": "eyJhbGciOiJFZERTQSIsImtpZCI6IkUyOUE4OTlDIiwibm9uY2UiOiI2M2E1MzYzMjI3NDYwYjVhIn0.eyJhdWQiOlsiYXBpLmV4YW1wbGUuY29tIl0sImV4cCI6MTUyNjMzMjczOSwiaWF0IjoxNTI2MzMyNzA5LCJpc3MiOiJhcGkuZXhhbXBsZS5jb20iLCJqdGkiOiIwM0VDNUVGNCIsIm5iZiI6MTUyNjMzMjY3OSwic3ViIjoiQ2xpZW50IFgiLCJ0andrIjp7ImFsZyI6IkVkRFNBIiwiY3J2IjoiRWQyNTUxOSIsImtpZCI6IkJFNjBERkM4LUsxIiwia3R5IjoiT0tQIiwieCI6IjVfVm9MbjhsY3R2djJ3RVhjdlNuREVGX0JPcDhycWlVbVFmM0dwdXJUcjAifX0.OYQZRUACGE9oc-kgcBLqL5DRaTvEh3QNChBN2zrXlnDthw0PJFD7quurjDM3HaEFKC2-Uot7K0nOq2ijYo73Cg",
  "kid": "BE60DFC8-K1",
  "nonce": "77f446e8d079cb20"
}
```

The `jwc` header field contains another compact-form JWT: [&#x1f441; jwt.io](https://jwt.io/#debugger-io?token=eyJhbGciOiJFZERTQSIsImtpZCI6IkUyOUE4OTlDIiwibm9uY2UiOiI2M2E1MzYzMjI3NDYwYjVhIn0.eyJhdWQiOlsiYXBpLmV4YW1wbGUuY29tIl0sImV4cCI6MTUyNjMzMjczOSwiaWF0IjoxNTI2MzMyNzA5LCJpc3MiOiJhcGkuZXhhbXBsZS5jb20iLCJqdGkiOiIwM0VDNUVGNCIsIm5iZiI6MTUyNjMzMjY3OSwic3ViIjoiQ2xpZW50IFgiLCJ0andrIjp7ImFsZyI6IkVkRFNBIiwiY3J2IjoiRWQyNTUxOSIsImtpZCI6IkJFNjBERkM4LUsxIiwia3R5IjoiT0tQIiwieCI6IjVfVm9MbjhsY3R2djJ3RVhjdlNuREVGX0JPcDhycWlVbVFmM0dwdXJUcjAifX0.OYQZRUACGE9oc-kgcBLqL5DRaTvEh3QNChBN2zrXlnDthw0PJFD7quurjDM3HaEFKC2-Uot7K0nOq2ijYo73Cg)


### Example JWC (decoded claims)

Extracted from the `jwc` header in the 'outer JWT', the claims of the 'inner JWT' contain the `tjwk` claim:
```
{
  "aud": [
    "api.example.com"
  ],
  "exp": 1526332739,
  "iat": 1526332709,
  "iss": "api.example.com",
  "jti": "03EC5EF4",
  "nbf": 1526332679,
  "sub": "Client X",
  "tjwk": {
    "alg": "EdDSA",
    "crv": "Ed25519",
    "kid": "BE60DFC8-K1",
    "kty": "OKP",
    "x": "5_VoLn8lctvv2wEXcvSnDEF_BOp8rqiUmQf3GpurTr0"
  }
}
```

### Full Bytes of an example chained JWT

[&#x1f441; jwt.io](https://jwt.io/#debugger-io?token=eyJhbGciOiJFZERTQSIsImp3YyI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW10cFpDSTZJa1V5T1VFNE9UbERJaXdpYm05dVkyVWlPaUkyTTJFMU16WXpNakkzTkRZd1lqVmhJbjAuZXlKaGRXUWlPbHNpWVhCcExtVjRZVzF3YkdVdVkyOXRJbDBzSW1WNGNDSTZNVFV5TmpNek1qY3pPU3dpYVdGMElqb3hOVEkyTXpNeU56QTVMQ0pwYzNNaU9pSmhjR2t1WlhoaGJYQnNaUzVqYjIwaUxDSnFkR2tpT2lJd00wVkROVVZHTkNJc0ltNWlaaUk2TVRVeU5qTXpNalkzT1N3aWMzVmlJam9pUTJ4cFpXNTBJRmdpTENKMGFuZHJJanA3SW1Gc1p5STZJa1ZrUkZOQklpd2lZM0oySWpvaVJXUXlOVFV4T1NJc0ltdHBaQ0k2SWtKRk5qQkVSa000TFVzeElpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklqVmZWbTlNYmpoc1kzUjJkakozUlZoamRsTnVSRVZHWDBKUGNEaHljV2xWYlZGbU0wZHdkWEpVY2pBaWZYMC5PWVFaUlVBQ0dFOW9jLWtnY0JMcUw1RFJhVHZFaDNRTkNoQk4yenJYbG5EdGh3MFBKRkQ3cXV1cmpETTNIYUVGS0MyLVVvdDdLMG5PcTJpallvNzNDZyIsImtpZCI6IkJFNjBERkM4LUsxIiwibm9uY2UiOiI3N2Y0NDZlOGQwNzljYjIwIn0.eyJhdWQiOlsiYXBpLmV4YW1wbGUuY29tIl0sImV4cCI6MTUyNjMzMjczOSwiaWF0IjoxNTI2MzMyNzA5LCJpc3MiOiJCRTYwREZDOCIsIm5iZiI6MTUyNjMzMjY3OSwic3ViIjoiQkU2MERGQzgifQ.ZZTFoqyc8rJmiIWfQX7IScnFUWn10JYG5T_M9rPcxivw-VBGqfGejwTvf0bAubCjlXJkeFoug4-SVlhGpc9jAA)

```
eyJhbGciOiJFZERTQSIsImp3YyI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW10cFpDSTZJa1V5T1VFNE9UbERJaXdpYm05dVkyVWlPaUkyTTJFMU16WXpNakkzTkRZd1lqVmhJbjAuZXlKaGRXUWlPbHNpWVhCcExtVjRZVzF3YkdVdVkyOXRJbDBzSW1WNGNDSTZNVFV5TmpNek1qY3pPU3dpYVdGMElqb3hOVEkyTXpNeU56QTVMQ0pwYzNNaU9pSmhjR2t1WlhoaGJYQnNaUzVqYjIwaUxDSnFkR2tpT2lJd00wVkROVVZHTkNJc0ltNWlaaUk2TVRVeU5qTXpNalkzT1N3aWMzVmlJam9pUTJ4cFpXNTBJRmdpTENKMGFuZHJJanA3SW1Gc1p5STZJa1ZrUkZOQklpd2lZM0oySWpvaVJXUXlOVFV4T1NJc0ltdHBaQ0k2SWtKRk5qQkVSa000TFVzeElpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklqVmZWbTlNYmpoc1kzUjJkakozUlZoamRsTnVSRVZHWDBKUGNEaHljV2xWYlZGbU0wZHdkWEpVY2pBaWZYMC5PWVFaUlVBQ0dFOW9jLWtnY0JMcUw1RFJhVHZFaDNRTkNoQk4yenJYbG5EdGh3MFBKRkQ3cXV1cmpETTNIYUVGS0MyLVVvdDdLMG5PcTJpallvNzNDZyIsImtpZCI6IkJFNjBERkM4LUsxIiwibm9uY2UiOiI3N2Y0NDZlOGQwNzljYjIwIn0.eyJhdWQiOlsiYXBpLmV4YW1wbGUuY29tIl0sImV4cCI6MTUyNjMzMjczOSwiaWF0IjoxNTI2MzMyNzA5LCJpc3MiOiJCRTYwREZDOCIsIm5iZiI6MTUyNjMzMjY3OSwic3ViIjoiQkU2MERGQzgifQ.ZZTFoqyc8rJmiIWfQX7IScnFUWn10JYG5T_M9rPcxivw-VBGqfGejwTvf0bAubCjlXJkeFoug4-SVlhGpc9jAA
```

## JOSE Extensions

JOSE Headers are in assigned in [an IANA registery](https://www.iana.org/assignments/jose/jose.xhtml).  `chainjwt` adds one header type.  JWT Claims are also in [an IANA registry](https://www.iana.org/assignments/jwt/jwt.xhtml) and `chainjwt` adds one claim type.

### JSON Web Signature and Encryption Header Parameters

- `jwc`: JWT Chain.  Contains string with a compact form JWT.  This JWT is intended to be longer lived, and to be signed by a trusted JWK.  This JWT contains an `tjwk` claim, which contains a JSON Web Key which can be used to validate the outer JWT.

### JSON Web Token Claims

- `tjwk`: Trusted JWK.  Contains a JSON-form JSON Web Key.  This MUST be a public key and the verifier should restrict the allowed algorithms. This JWK can be used the validate the outer JWT.


# License

`chainjwt` is licensed under the Apache License Version 2.0. See the [LICENSE file](./LICENSE) for details.
