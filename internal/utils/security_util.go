package utils

import (
	"crypto/sha1"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
)

type authClaim struct {
	UserId int      `json:"userId"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

// Generates a Jwt Token return a string or error
func GenerateJwtToken(userId int, roles []string, expire time.Duration) (string, error) {
	claims := authClaim{
		userId,
		roles,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expire)),
		},
	}
	claimToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return claimToken.SignedString(jwtSecret)
}

// ValidatesJWtAndGetClaims the JWT Key and return the claims
func ValidateJwtAndGetClaims(tokenString string) (map[string]interface{}, error) {
	res := make(map[string]interface{})
	token, err := jwt.ParseWithClaims(tokenString, &authClaim{}, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if claims, ok := token.Claims.(*authClaim); ok && token.Valid {
		res["userId"] = claims.UserId
		res["roles"] = claims.Roles
		return res, nil
	}

	return nil, err
}

// GenerateOpaqueToken function to generate random tokens
func GenerateOpaqueToken(randomCharsLength int) string {
	var alphaNum = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	randomLetters := make([]rune, randomCharsLength)
	randomSource := rand.NewSource(time.Now().UnixNano())
	random := rand.New(randomSource)
	fmt.Printf("randomLetters = %v - randomSource = %v - random = %v\n", randomLetters, randomSource, random)
	for i := range randomLetters {
		randomLetters[i] = alphaNum[random.Intn(len(randomLetters))]
	}
	// Convert to sha1 string
	randomString := string(randomLetters)
	return fmt.Sprintf("%x", sha1.Sum([]byte(randomString)))
}

// Generate Random Digits
func GenerateRandomDigits(length int) string {
	randomSource := rand.NewSource(time.Now().UnixNano())
	random := rand.New(randomSource)
	randNumber := make([]string, length)
	for i := range randNumber {
		randNumber[i] = strconv.Itoa(random.Intn(9))
	}
	return strings.Join(randNumber, "")
}

// Function to check for special chars
func checkSpecialChars(specialChar rune) bool {
	specialChars := `@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`
	for _, char := range specialChars {
		if char == specialChar {
			return true
		}
	}
	return false
}

// check strong password
func IsStrongPassword(password string) bool {
	if len(password) <= 8 {
		return false
	}

	var (
		isUpper, isLower, isDigit, isSpecialChar bool
	)

	for _, char := range password {
		if unicode.IsDigit(char) {
			isDigit = true
		}
		if unicode.IsUpper(char) {
			isUpper = true
		}
		if unicode.IsLower(char) {
			isLower = true
		}
		if checkSpecialChars(char) {
			isSpecialChar = true
		}
	}

	if !isUpper || !isDigit || !isLower || !isSpecialChar {
		return false
	}

	return true
}
