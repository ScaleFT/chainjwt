package chainjwt

import (
	"github.com/ScaleFT/xjwt"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type TrustJWKClaim struct {
	TrustJWK jose.JSONWebKey `json:"tjwk"`
}

type CreateOptions struct {
	// Claims contains the core claims of the JWT.
	Claims jwt.Claims
	// ExtraClaims are added to the JWT Builder. See <https://godoc.org/gopkg.in/square/go-jose.v2/jwt#Builder> for details.
	ExtraClaims []interface{}
	// Key is the "outer" Signing Key to use to construct the JWT
	Key jose.SigningKey
	// JWSChain contains the "inner" JWT that this JWT is chained from.
	JWSChain string
}

func Create(opts CreateOptions) (string, error) {
	sopts := (&jose.SignerOptions{
		NonceSource: &xjwt.RandomNonce{Size: 8},
	}).WithHeader("jwc", opts.JWSChain)

	sig, err := jose.NewSigner(opts.Key, sopts)
	if err != nil {
		return "", err
	}
	c := jwt.Signed(sig).Claims(opts.Claims)
	for _, extra := range opts.ExtraClaims {
		c = c.Claims(extra)
	}

	raw, err := c.CompactSerialize()
	if err != nil {
		return "", err
	}
	return raw, nil
}
