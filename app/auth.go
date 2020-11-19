package app

import (
	"authTest/models"
	u "authTest/utils"
	"context"
	b64 "encoding/base64"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"os"
	"strings"
)

type AccessDetails struct {
	AccessUuid string
	UserId     uint64
}

/*
JWT claims struct
*/
type Token struct {
	UserId uint
	jwt.StandardClaims
}

func Login(login, password string) map[string]interface{} {
	account, ok := models.CheckLoginForm(login, password)
	if !ok {
		return u.Message(false, "Please provide valid login details")
	}
	tp, rtString, err := models.CreateToken(account.ID)
	if err != nil {
		log.Println("CreateToken err")
		return u.Message(false, "Error on server side")
	}
	rtEncoded := b64.StdEncoding.EncodeToString([]byte(*rtString))
	saveErr := models.SaveTokenPair(*tp)
	if saveErr != nil {
		log.Println("SaveTokenPair err")
		return u.Message(false, "Error on server side")
	}
	tokens := map[string]string{
		"access_token":  tp.AccessToken,
		"refresh_token": rtEncoded,
	}

	resp := u.Message(true, "Logged In")
	resp["account"] = account
	resp["tokens"] = tokens
	return resp
}

var JwtAuthentication = func(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		notAuth := []string{"/register", "/login", "/logout", "/token/deleteall", "/token/refresh"} //List of endpoints that doesn't require auth
		requestPath := r.URL.Path                                                                   //current request path

		//check if request does not need authentication, serve the request if it doesn't need it
		for _, value := range notAuth {

			if value == requestPath {
				next.ServeHTTP(w, r)
				return
			}
		}

		response := make(map[string]interface{})
		tokenHeader := r.Header.Get("Authorization") //Grab the token from the header

		if tokenHeader == "" { //Token is missing, returns with error code 403 Unauthorized
			response = u.Message(false, "Missing auth token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		splitted := strings.Split(tokenHeader, " ") //The token normally comes in format `Bearer {token-body}`, we check if the retrieved token matched this requirement
		if len(splitted) != 2 {
			response = u.Message(false, "Invalid/Malformed auth token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		tokenPart := splitted[1] //Grab the token part, what we are truly interested in

		token, err := jwt.Parse(tokenPart, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("ACCESS_SECRET")), nil
		})

		if err != nil { //Malformed token, returns with http code 403 as usual
			response = u.Message(false, "Malformed authentication token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		acc, err := models.GetDB().ValidAccessToken(token.Raw)
		if err != nil {
			response = u.Message(false, "Token is not valid.")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			log.Println("access token is not in database")
			return
		} else {
			if !token.Valid { //Token is invalid, but in database
				response = u.Message(false, "Token is not valid, but exist in database. Try to refresh token pair.")
				w.WriteHeader(http.StatusForbidden)
				w.Header().Add("Content-Type", "application/json")
				u.Respond(w, response)
				return
			}
		}

		//Everything went well, proceed with the request and set the caller to the user retrieved from the parsed token
		fmt.Println("User logged in %", acc.ID) //Useful for monitoring
		ctx := context.WithValue(r.Context(), "user", acc.ID)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r) //proceed in the middleware chain!
	})
}
