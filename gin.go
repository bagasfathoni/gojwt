package gojwt

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type AuthHeader struct {
	AuthorizationHeader string `header:"Authorization"`
}

// RequireToken can be implemented as middleware when using Gin to an endpoint/route
func (j *JwtConfig) RequireToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := AuthHeader{}
		if err := c.ShouldBindHeader(&h); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
		}
		tokenString := strings.Replace(h.AuthorizationHeader, "Bearer ", "", -1)
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}
		token, err := j.VerifyToken(tokenString)
		if err != nil {
			log.Println(err)
		}
		result, err := j.FetchTokenFromRedis(token)
		if result == "" || err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

		if token != "" {
			c.Set("issuer", result)
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			c.Abort()
			return
		}

	}
}
