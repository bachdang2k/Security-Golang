package middlewares

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/bachdang2k/security-golang/internal/utils"
)

func JwtAuth(handler func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	const ErrorMessageInvalidToken string = "Invalid Token"
	const ErrorMessageProvideValidToken string = "Failed provide a valid token in request header as Token"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearerToken := r.Header.Get("Authorization")
		token := strings.Replace(bearerToken, "Bearer ", "", -1)
		if token != "" {
			claims, err := utils.ValidateJwtAndGetClaims(token)
			if err != nil {
				utils.JSONError(w, ErrorMessageInvalidToken, http.StatusForbidden)
				log.Println(ErrorMessageInvalidToken)
				return
			}
			ctx := context.WithValue(r.Context(), "claims", claims)
			handler(w, r.WithContext(ctx))
		} else {
			utils.JSONError(w, ErrorMessageProvideValidToken, http.StatusForbidden)
			log.Println(ErrorMessageProvideValidToken)
			return
		}
	})
}

func Method(method string, handler func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			utils.JSONError(w, "This Method Not Allowed", http.StatusBadRequest)
			return
		}
		handler(w, r)
	})
}

func LogRequest(handler http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}
