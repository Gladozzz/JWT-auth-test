package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"authTest/app"
	"authTest/controllers"
	"net/http"
	"os"
)

func main() {

	router := mux.NewRouter()

	router.HandleFunc("/register", controllers.CreateAccount).Methods("POST")
	router.HandleFunc("/login", controllers.AuthenticateWithLogin).Methods("POST") //маршрут 1 Первый маршрут выдает пару Access, Refresh токенов для пользователя с идентификатором (GUID) указанным в параметре запроса
	router.HandleFunc("/token/refresh", controllers.RefreshAuth).Methods("POST") //маршрут 2 Второй маршрут выполняет Refresh операцию на пару Access, Refresh токенов
	router.HandleFunc("/logout", controllers.Logout).Methods("POST") //маршрут 3 Третий маршрут удаляет конкретный Refresh токен из базы
	router.HandleFunc("/token/deleteall", controllers.DeleteAllTokensOfUser).Methods("POST") //маршрут 4  удаляет все Refresh токены из базы для конкретного пользователя


	router.Use(app.JwtAuthentication) //attach JWT auth middleware

	//router.NotFoundHandler = app.NotFoundHandler

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000" //localhost
	}

	fmt.Println(port)

	err := http.ListenAndServe(":"+port, router) //Launch the app, visit localhost:8000/api
	if err != nil {
		fmt.Print(err)
	}
}
