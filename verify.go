package chainjwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/ScaleFT/xjwt"
	jose "gopkg.in/square/go-jose.v2"
)

type VerifyConfig struct {
	ExpectedIssuer   string
	ExpectedAudience string
	Now              func() time.Time
	CheckJTIRevoked  func(string) error
	KeySet           *jose.JSONWebKeySet
}

type VerifyResult struct {
	Payload      []byte
	InnerPayload []byte
	JWK          *jose.JSONWebKey
}

// See header registery:
// 	https://www.iana.org/assignments/jose/jose.xhtml
// What we are doing is close to x5c, an X.509 chain.  So, call our header `jwc`, JWT Chain.
type outerHeader struct {
	JWSChain string `json:"jwc,omitempty"`
}

func decodeBytes(enc *base64.Encoding, d []byte) ([]byte, error) {
	dbuf := make([]byte, enc.DecodedLen(len(d)))
	n, err := enc.Decode(dbuf, d)
	return dbuf[:n], err
}

func innerJWT(input []byte) ([]byte, error) {
	parts := bytes.Split(input, []byte("."))
	if len(parts) != 3 {
		return nil, xjwt.NewVerifyErr("chainjwt: compact JWS format must have three parts", xjwt.JWT_MALFORMED)
	}

	rawHeader, err := decodeBytes(base64.RawURLEncoding, parts[0])
	if err != nil {
		return nil, err
	}

	var parsed outerHeader
	err = json.Unmarshal(rawHeader, &parsed)
	if err != nil {
		return nil, err
	}

	if len(parsed.JWSChain) < minInnerJWTSize {
		return nil, xjwt.NewVerifyErr("chainjwt: inner JWT is too small", xjwt.JWT_MALFORMED)
	}

	if len(parsed.JWSChain) > maxInnerJWTSize {
		return nil, xjwt.NewVerifyErr("chainjwt: inner JWT is too large", xjwt.JWT_MALFORMED)
	}
	return []byte(parsed.JWSChain), nil
}

type innerClaims struct {
	ID       string          `json:"jti,omitempty"`
	TrustJWK json.RawMessage `json:"tjwk,omitempty"`
}

func Verify(input []byte, vc *VerifyConfig) (*VerifyResult, error) {
	inner, err := innerJWT(input)
	if err != nil {
		return nil, err
	}

	innerPayload, err := xjwt.VerifyRaw(inner, xjwt.VerifyConfig{
		ExpectedIssuer:   vc.ExpectedIssuer,
		ExpectedAudience: vc.ExpectedAudience,
		KeySet:           vc.KeySet,
		Now:              vc.Now,
	})
	if err != nil {
		return nil, err
	}

	ic := innerClaims{}
	err = json.Unmarshal(innerPayload, &ic)
	if err != nil {
		return nil, err
	}

	if vc.CheckJTIRevoked != nil {
		err := vc.CheckJTIRevoked(ic.ID)
		if err != nil {
			return nil, err
		}
	}

	if len(ic.TrustJWK) < minTrustJWKSize {
		return nil, xjwt.NewVerifyErr("chainjwt: inner TrustJWK is too small", xjwt.JWT_MALFORMED)
	}

	jwk := jose.JSONWebKey{}
	err = jwk.UnmarshalJSON(ic.TrustJWK)
	if err != nil {
		return nil, err
	}

	if !jwk.Valid() {
		return nil, xjwt.NewVerifyErr("chainjwt: inner TrustJWK is too not valid", xjwt.JWT_MALFORMED)
	}

	if !jwk.IsPublic() {
		return nil, xjwt.NewVerifyErr("chainjwt: inner TrustJWK must be a public key", xjwt.JWT_MALFORMED)
	}

	payload, err := xjwt.VerifyRaw(input, xjwt.VerifyConfig{
		ExpectedAudience: vc.ExpectedAudience,
		KeySet: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				jwk,
			},
		},
		Now: vc.Now,
	})

	// TODO(pquerna): verify audience of outer
	// TODO(pquerna): should the subject of inner and outer match?
	return &VerifyResult{
		Payload:      payload,
		JWK:          &jwk,
		InnerPayload: innerPayload,
	}, nil
}

const (
	minTrustJWKSize = 16
	minInnerJWTSize = 64
	maxInnerJWTSize = 16000
)
