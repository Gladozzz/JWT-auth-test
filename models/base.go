package models

import (
	"context"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
)

var db *DB

type DB struct {
	client *mongo.Client
}

func (_db *DB) getAccountByUid(uid string) (*Account, error) {
	var collection = db.client.Database("auth").Collection("Accounts")
	var filter = bson.M{"id": uid}
	var result Account
	err := collection.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		return nil, err
	} else {
		return &result, nil
	}
}

func (_db *DB) getAccountByLogin(login string) (*Account, error) {
	var collection = db.client.Database("auth").Collection("Accounts")
	var filter = bson.M{"login": login}
	var result Account
	err := collection.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		return nil, err
	} else {
		return &result, nil
	}
}

func (_db *DB) addTokenToAccount(tp TokenPair) error {
	var collection = db.client.Database("auth").Collection("Accounts")
	filter := bson.M{"id": tp.UserId}
	update := bson.M{"$push": bson.M{"tokens": tp}}
	updateResult, err := collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		log.Println("addTokenToAccount err")
		log.Println(err)
		return err
	} else {
		fmt.Println("addTokenToAccount updated result ", updateResult.UpsertedID)
		return nil
	}
}

func (_db *DB) RemoveTokenFromAccount(at string) error {
	var collection = db.client.Database("auth").Collection("Accounts")
	filter := bson.M{"tokens": bson.M{"$elemMatch": bson.M{"accesstoken": at}}}
	update := bson.M{"$pull": bson.M{"tokens": bson.M{"accesstoken": at}}}
	updateResult, err := collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		log.Println("RemoveTokenFromAccount can't find account with at: " + at)
		log.Println(err)
		return err
	} else {
		fmt.Println("RemoveTokenFromAccount updated result ", updateResult.UpsertedID)
		return nil
	}
}

func (_db *DB) deleteAllTokensFromAccount(lf LoginForm) error {
	var collection = db.client.Database("auth").Collection("Accounts")
	var filter = bson.M{"login": lf.Login}
	update := bson.D{
		{"$set", bson.D{
			{"tokens", []TokenPair{}},
		}},
	}
	updateResult, err := collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		log.Println("deleteAllTokensFromAccount err")
		log.Println(err)
		return err
	} else {
		fmt.Println("deleteAllTokensFromAccount updated result ", updateResult.UpsertedID)
		return nil
	}
}

func (_db *DB) refreshTokenPair(rt string) (*string, *string, error) {
	userID, err := getUserIdFromRefreshToken(rt)
	if err != nil {
		return nil, nil, err
	}
	var collection = db.client.Database("auth").Collection("Accounts")
	var filter = bson.M{"id": userID}
	var result Account
	err = collection.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		log.Println("refreshTokenPair err")
		log.Println(err)
		return nil, nil, err
	}
	for _, token := range result.Tokens {
		rtHashed := token.HashedRefreshToken
		err = bcrypt.CompareHashAndPassword(rtHashed, []byte(rt))
		if err == nil {
			newTP, atString, rtString, err := CreateToken(result.ID)
			if err != nil {
				log.Println("refreshTokenPair err in CreateToken")
				return nil, nil, err
			}
			rtHashed, err = bcrypt.GenerateFromPassword(newTP.HashedRefreshToken, bcrypt.DefaultCost)
			if err != nil {
				log.Println("refreshTokenPair err in GenerateFromPassword")
				log.Println(err)
				return nil, nil, err
			}
			var filter = bson.M{"tokens": bson.M{"$elemMatch": bson.M{"accessuuid": token.AccessUuid}}, "id": result.ID}
			update := bson.D{
				{"$set", bson.D{
					{"tokens.$.atexpires", newTP.AtExpires},
					{"tokens.$.accessuuid", newTP.AccessUuid},
					{"tokens.$.refreshuuid", newTP.RefreshUuid},
					{"tokens.$.rtexpires", newTP.RtExpires},
					{"tokens.$.hashedrefreshtoken", rtHashed},
				}},
			}
			updateResult, err := collection.UpdateOne(context.TODO(), filter, update)
			if err != nil {
				log.Println("refreshTokenPair err")
				log.Println(err)
				return nil, nil, err
			} else {
				fmt.Println("refreshTokenPair updated result ", updateResult.UpsertedID)
				return atString, rtString, nil
			}
		}
	}
	err = errors.New("Can't find account with this refresh token")
	fmt.Println("refreshTokenPair err", err)
	return nil, nil, err
}

func (_db *DB) ValidAccessToken(at string) (*Account, error) {
	var collection = db.client.Database("auth").Collection("Accounts")
	var filter = bson.M{"tokens": bson.M{"$elemMatch": bson.M{"accesstoken": at}}}
	var result Account
	err := collection.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		log.Println("ValidAccessToken can't find out account with access token: " + at)
		log.Println(err)
		return nil, err
	}
	return &result, nil
}

func (_db *DB) putAccount(ac Account) error {
	var collection = db.client.Database("auth").Collection("Accounts")
	for i, v := range ac.Tokens {
		rtHashed, _ := bcrypt.GenerateFromPassword(v.HashedRefreshToken, bcrypt.DefaultCost)
		ac.Tokens[i].HashedRefreshToken = rtHashed
	}
	insertResult, err := collection.InsertOne(context.TODO(), ac)
	if err != nil {
		log.Println("putAccount err: Can't insert account")
		log.Println(err)
		return err
	}
	fmt.Println("Inserted a single document: ", insertResult.InsertedID)
	return nil
}

func (_db *DB) removeAccountByID(UserId string) error {
	var collection = db.client.Database("auth").Collection("Accounts")
	var filter = bson.M{"id": UserId}
	deleteResult, err := collection.DeleteOne(context.TODO(), filter)
	if err != nil {
		log.Println("removeAccountByID err: Can't remove account")
		log.Println(err)
		return err
	} else {
		fmt.Println("Deleted a single document: ", deleteResult.DeletedCount)
		return nil
	}
}

/*
JWT claims struct
*/
type Token struct {
	UserId uint
	jwt.StandardClaims
}

//func getUserIdFromAccessToken(tokenString string) (*string, error) {
//	return getUserIdFromToken(tokenString, func(token *jwt.Token) (interface{}, error) {
//		return []byte(os.Getenv("ACCESS_SECRET")), nil
//	})
//}
func getUserIdFromRefreshToken(tokenString string) (*string, error) {
	return getUserIdFromToken(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})
}
func getUserIdFromToken(tokenString string, keyfunc jwt.Keyfunc) (*string, error) {
	//tk := &Token{}
	token, err := jwt.Parse(tokenString, keyfunc)
	if err != nil {
		log.Println("getUserIdFromToken err")
		log.Println(err)
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		userId, ok := claims["user_id"].(string)
		if !ok {
			err = errors.New("jwt.Claims is not valid")
			return nil, err
		}
		return &userId, nil
	}
	err = errors.New("token is not valid")
	fmt.Println("getUserIdFromToken err")
	fmt.Println(err)
	return nil, err
}

func init() {
	// loads values from .env into the system
	if err := godotenv.Load(); err != nil {
		log.Fatal("No .env file found")
	}
	db = new(DB)

	username := os.Getenv("ATLAS_USERNAME")
	password := os.Getenv("ATLAS_PASSWORD")
	if username == "" || password == "" {
		log.Fatal("Cannot get env variables from .env file")
	}
	uri := "mongodb+srv://" + username + ":" + password + "@cluster0.p7vzu.mongodb.net/auth?retryWrites=true&w=majority"

	_client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(
		uri,
	))
	if err != nil {
		log.Fatal(err)
	}
	db.client = _client
}

func GetDB() *DB {
	return db
}
