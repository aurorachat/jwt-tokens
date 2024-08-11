package tokens

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"strings"
)

var secretToken []byte

func SetSecretToken(token []byte) {
	secretToken = token
}

func GetJWTClaims(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return secretToken, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func CreateJWT(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(secretToken)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ValidateToken(token string) (*jwt.MapClaims, error) {
	resultToken, found := strings.CutPrefix(token, "Bearer ")
	if !found {
		return nil, errors.New("invalid token")
	}
	claims, err := GetJWTClaims(resultToken)
	if err != nil {
		return nil, err
	}
	return &claims, nil
}
