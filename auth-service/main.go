package main

import (
	"context"
	"log"
	"auth-service/handlers"
	"auth-service/middlewares"
	"time"

	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	e := echo.New()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}
	userCollection := client.Database("finance-app-db").Collection("users")

	authHandler := &handlers.AuthHandler{UserCollection: userCollection}

	e.POST("/register", authHandler.Register)
	e.POST("/login", authHandler.Login)
	e.POST("/refresh", authHandler.Refresh)
	e.GET("/protected", authHandler.Protected, middlewares.JWTMiddleware)

	e.Logger.Fatal(e.Start(":8088"))
}
