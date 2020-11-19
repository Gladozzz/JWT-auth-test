package controllers

import (
	"authTest/app"
	"authTest/models"
	u "authTest/utils"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
)

/*
JWT claims struct
*/
type Token struct {
	UserId uint
	jwt.StandardClaims
}

var CreateAccount = func(w http.ResponseWriter, r *http.Request) {

	lf := &models.LoginForm{}
	fmt.Println("CreateAccount")
	err := json.NewDecoder(r.Body).Decode(lf) //decode the request body into struct and failed if any error occur
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	resp := models.Register(lf) //Create account
	u.Respond(w, resp)
}

var AuthenticateWithLogin = func(w http.ResponseWriter, r *http.Request) {

	lf := &models.LoginForm{}
	fmt.Println("AuthenticateWithLogin")
	err := json.NewDecoder(r.Body).Decode(lf) //decode the request body into struct and failed if any error occur
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	resp := app.Login(lf.Login, lf.Password)
	u.Respond(w, resp)
}

type RefreshTokenForm struct {
	RefreshToken string `json:"refresh_token"`
}

var RefreshAuth = func(w http.ResponseWriter, r *http.Request) {

	rtf := &RefreshTokenForm{}
	err := json.NewDecoder(r.Body).Decode(rtf) //decode the request body into struct and failed if any error occur
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	resp := models.RefreshTokenPair(rtf.RefreshToken)
	u.Respond(w, resp)
}

type AccessTokenForm struct {
	AccessToken string `json:"access_token"`
}

var Logout = func(w http.ResponseWriter, r *http.Request) {

	atf := &AccessTokenForm{}
	err := json.NewDecoder(r.Body).Decode(atf) //decode the request body into struct and failed if any error occur
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	resp := models.DeleteTokenPair(atf.AccessToken)
	u.Respond(w, resp)
}

var DeleteAllTokensOfUser = func(w http.ResponseWriter, r *http.Request) {

	lf := &models.LoginForm{}
	err := json.NewDecoder(r.Body).Decode(lf) //decode the request body into struct and failed if any error occur
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	_, ok := models.CheckLoginForm(lf.Login, lf.Password)
	if !ok {
		u.Respond(w, u.Message(false, "Invalid credentials"))
	}
	resp := models.DeleteAllTokenPairsOfUser(*lf)
	u.Respond(w, resp)
}
