package gojwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

// Create new signed JWT with specified duration
func (j *JwtConfig) CreateToken(tokenDuration time.Duration, issuer string, options ...map[string]interface{}) (*JwtDetails, error) {
	jwtEnd := time.Now().UTC().Add(tokenDuration)
	claims := jwt.StandardClaims{
		Issuer:    issuer,
		IssuedAt:  time.Now().UTC().Unix(),
		ExpiresAt: jwtEnd.Unix(),
	}
	newJwtClaims := jwt.NewWithClaims(j.JwtSigningMethod, claims)
	newSignedToken, err := newJwtClaims.SignedString([]byte(j.JwtSignatureKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create a signed token with error: %s", err.Error())
	}
	return &JwtDetails{
		Token:     newSignedToken,
		CreatedAt: time.Now().UTC(),
		IssuedAt:  time.Now().UTC().Unix(),
		ExpiresAt: jwtEnd.Unix(),
	}, nil
}

// Store a token to Redis
func (j *JwtConfig) StoreTokenToRedis(issuer string, jwtDetails *JwtDetails) error {
	at := time.Unix(jwtDetails.ExpiresAt, 0)
	now := time.Now()
	err := j.Client.Set(context.Background(), fmt.Sprintf("token-issuer-%s", issuer), jwtDetails.Token, at.Sub(now)).Err()
	if err != nil {
		return fmt.Errorf("failed to store token to redis with error: %s", err.Error())
	}
	return nil
}

// Fetch a stored token from Redis
func (j *JwtConfig) FetchTokenFromRedis(issuer string) (string, error) {
	if issuer != "" {
		token, err := j.Client.Get(context.Background(), fmt.Sprintf("token-issuer-%s", issuer)).Result()
		if err != nil {
			return "", fmt.Errorf("failed to get token from redis with error: %s", err.Error())
		}
		return token, nil
	} else {
		return "", errors.New("invalid access token")
	}
}

// Verify a JWT and get the Issuer
func (j *JwtConfig) VerifyToken(tokenToCheck string) (string, error) {
	token, err := jwt.Parse(tokenToCheck, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method")
		} else if method != j.JwtSigningMethod {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(j.JwtSignatureKey), nil
	})
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["iss"] != j.ApplicationName {
		return "", fmt.Errorf("failed to verify token details with error: %s", err.Error())
	}
	issuer := claims["issuer"].(string)
	return issuer, nil
}
