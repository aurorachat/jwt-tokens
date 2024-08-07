package wrappers

import (
	"github.com/aurorachat/jwt-tokens/tokens"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

func GinProtectedRoute() gin.HandlerFunc {
	return func(c *gin.Context) {
		authToken := c.Request.Header.Get("Authorization")
		if authToken == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		authToken, found := strings.CutPrefix(authToken, "Bearer ")

		if !found {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, err := tokens.GetJWTClaims(authToken)

		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set("jwt-claims", claims)
		c.Next()
	}
}
