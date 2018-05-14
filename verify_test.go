package chainjwt

import (
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/ScaleFT/xjwt"
	"github.com/stretchr/testify/require"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestVerifyBasic(t *testing.T) {
	innerPub, innerKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	outerPub, outerKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	innerSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{
		Key:       innerKey,
		KeyID:     "E29A899C",
		Algorithm: string(jose.EdDSA),
	}}, &jose.SignerOptions{
		NonceSource: &xjwt.RandomNonce{Size: 8},
	})
	require.NoError(t, err)

	now := time.Now()

	innerJWT, err := jwt.Signed(innerSigner).Claims(jwt.Claims{
		ID:        "03EC5EF4",
		Subject:   "Client X",
		NotBefore: jwt.NewNumericDate(now.Add(time.Second * -30)),
		IssuedAt:  jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(time.Second * 30)),
		Issuer:    "api.example.com",
		Audience:  jwt.Audience{"api.example.com"},
	}).Claims(
		&TrustJWKClaim{
			TrustJWK: jose.JSONWebKey{
				Key:       outerPub,
				KeyID:     "BE60DFC8-K1",
				Algorithm: string(jose.EdDSA),
			},
		},
	).CompactSerialize()
	require.NoError(t, err)
	require.NotEmpty(t, innerJWT)

	claims := jwt.Claims{
		Subject:   "BE60DFC8",
		NotBefore: jwt.NewNumericDate(now.Add(time.Second * -30)),
		IssuedAt:  jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(time.Second * 30)),
		Issuer:    "BE60DFC8",
		Audience:  jwt.Audience{"api.example.com"},
	}
	output, err := Create(CreateOptions{
		Claims: claims,
		Key: jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{
			Key:       outerKey,
			KeyID:     "BE60DFC8-K1",
			Algorithm: string(jose.EdDSA),
		}},
		JWSChain: innerJWT,
	})
	require.NoError(t, err)
	require.NotEmpty(t, output)
	// spew.Dump(output)

	rv, err := Verify([]byte(output), &VerifyConfig{
		ExpectedIssuer:   "api.example.com",
		ExpectedAudience: "api.example.com",
		KeySet: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				jose.JSONWebKey{
					Key:       innerPub,
					KeyID:     "E29A899C",
					Algorithm: string(jose.EdDSA),
				},
			},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, rv)
}
