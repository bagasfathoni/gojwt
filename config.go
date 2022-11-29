package gojwt

import (
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
)

type JwtConfig struct {
	ApplicationName  string
	JwtSigningMethod *jwt.SigningMethodHMAC
	JwtSignatureKey  string
	LifeDuration     time.Duration
	Client           *redis.Client
}

type JwtDetails struct {
	Token     string
	CreatedAt time.Time
	IssuedAt  int64
	ExpiresAt int64
}

// type JwtClaims struct {
// 	jwt.StandardClaims
// 	Issuer string
// }
