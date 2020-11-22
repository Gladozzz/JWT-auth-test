package models

import (
	u "authTest/utils"
	b64 "encoding/base64"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/twinj/uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"time"
)

type TokenPair struct {
	UserId             string
	AccessUuid         string
	RefreshUuid        string
	HashedRefreshToken []byte
	AtExpires          int64
	RtExpires          int64
}

//model for db and parsing requests
type TokenForm struct {
	AccessToken  string
	RefreshToken string
}

//model for db and parsing requests
type LoginForm struct {
	Login    string
	Password string
}

//a struct to rep user account
type Account struct {
	ID       string
	Login    string
	Password string
	Tokens   []TokenPair
}

func CreateToken(userid string) (*TokenPair, *string, *string, error) {
	tp := &TokenPair{}
	tp.UserId = userid
	tp.AtExpires = time.Now().Add(time.Hour * 24).Unix()
	tp.AccessUuid = uuid.NewV4().String()

	tp.RtExpires = time.Now().Add(time.Hour * 24 * 30).Unix()
	tp.RefreshUuid = uuid.NewV4().String()

	var err error
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = tp.AccessUuid
	atClaims["user_id"] = userid
	atClaims["exp"] = tp.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS512, atClaims)
	atString, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, nil, nil, err
	}
	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = tp.RefreshUuid
	atClaims["refresh_uuid"] = tp.RefreshUuid
	rtClaims["access_uuid"] = tp.AccessUuid
	rtClaims["access_token"] = atString
	rtClaims["user_id"] = userid
	rtClaims["exp"] = tp.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS512, rtClaims)
	rtString, err := rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	rtBytes, _ := bcrypt.GenerateFromPassword([]byte(rtString), bcrypt.DefaultCost)
	tp.HashedRefreshToken = rtBytes
	if err != nil {
		log.Println("CreateToken err")
		log.Println(err)
		return nil, nil, nil, err
	}
	return tp, &atString, &rtString, nil
}

//Validate incoming user details...
func (lf *LoginForm) Validate() (map[string]interface{}, bool) {
	if len(lf.Login) < 4 {
		return u.Message(false, "Login is required"), false
	}

	if len(lf.Password) < 6 {
		return u.Message(false, "Password is required"), false
	}

	//Login must be unique
	sameLoginAcc, err := GetDB().getAccountByLogin(lf.Login)
	if err != nil {
		log.Println("getAccountByLogin err")
		log.Println(err)
	}
	if sameLoginAcc != nil {
		return u.Message(false, "Login already in use by another user."), false
	}

	return u.Message(false, "Requirement passed"), true
}

func Register(lf *LoginForm) map[string]interface{} {
	if resp, ok := lf.Validate(); !ok {
		return resp
	}

	var account = Account{}
	account.Login = lf.Login
	//Create GUID
	account.ID = uuid.NewV4().String()
	account.Tokens = []TokenPair{}

	//Hashing password
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(lf.Password), bcrypt.DefaultCost)
	account.Password = string(hashedPassword)

	//Create TokenPair
	tp, atString, rtString, err := CreateToken(account.ID)
	if err != nil {
		response := u.Message(true, "Some error on server side")
		return response
	} else {
		account.Tokens = append(account.Tokens, *tp)
	}

	//Put new account to DB
	if err = GetDB().putAccount(account); err != nil {
		return u.Message(false, "Failed to create account, connection error.")
	}

	account.Password = "" //delete password
	lf.Password = ""
	account.Tokens = []TokenPair{}

	response := u.Message(true, "Account has been created")
	response["account"] = account
	tokens := map[string]string{
		"access_token":  *atString,
		"refresh_token": *rtString,
	}
	response["tokens"] = tokens
	return response
}

func CheckLoginForm(login, password string) (*Account, bool) {
	account, err := GetDB().getAccountByLogin(login)
	if err != nil {
		return nil, false
	}
	account.Tokens = nil

	err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(password))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword { //Password does not match!
		return nil, false
	}
	account.Password = ""
	return account, true
}

func RefreshTokenPair(rt string) map[string]interface{} {
	rtDecoded, err := b64.StdEncoding.DecodeString(rt)
	if err != nil {
		log.Println("RefreshTokenPair err in DecodeString")
		log.Println(err)
		return u.Message(false, "HashedRefreshToken must be an base64 encoded string")
	}
	//log.Println(string(rtDecoded))
	at, newRT, err := GetDB().refreshTokenPair(string(rtDecoded))
	if err != nil {
		return u.Message(false, "Wrong HashedRefreshToken")
	}
	tokens := map[string]string{
		"access_token":  *at,
		"refresh_token": *newRT,
	}
	resp := u.Message(true, "TokenPair was refreshed")
	resp["tokens"] = tokens
	return resp
}

func DeleteTokenPair(at string) map[string]interface{} {
	//atDecoded := b64.StdEncoding.DecodeString(at)
	err := GetDB().RemoveTokenFromAccount(at)
	if err != nil {
		return u.Message(false, "Wrong AccessToken")
	}
	resp := u.Message(true, "TokenPair was removed")
	return resp
}

func DeleteAllTokenPairsOfUser(lf LoginForm) map[string]interface{} {
	err := GetDB().deleteAllTokensFromAccount(lf)
	if err != nil {
		log.Println("DeleteAllTokenPairsOfUser err")
		log.Println(err)
		return u.Message(false, "Wrong account credentials")
	}
	resp := u.Message(true, "all tokens was deleted")
	return resp
}

func SaveTokenPair(tp TokenPair) error {
	err := GetDB().addTokenToAccount(tp)
	if err != nil {
		return err
	}
	return nil
}
