package handlers

import (
	"context"
	"time"
	"auth-service/models"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"go.mongodb.org/mongo-driver/bson"
)

var jwtSecret = []byte("your-secret-key")

type AuthHandler struct {
	UserCollection *mongo.Collection
}

func (h *AuthHandler) Register(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user := new(models.User)
	if err := c.Bind(user); err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hash)

	_, err = h.UserCollection.InsertOne(ctx, user)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "User exists or DB error"})
	}

	return c.JSON(http.StatusCreated, echo.Map{"message": "User registered"})
}

func (h *AuthHandler) Login(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reqUser := new(models.User)
	if err := c.Bind(reqUser); err != nil {
		return err
	}

	var dbUser models.User
	err := h.UserCollection.FindOne(ctx, bson.M{"username": reqUser.Username}).Decode(&dbUser)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid username"})
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(reqUser.Password))
	if err != nil {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "Invalid password"})
	}

	accessToken, err := generateAccessToken(dbUser.Username)
	if err != nil {
		return err
	}
	refreshToken, err := generateRefreshToken(dbUser.Username)
	if err != nil {
		return err
	}

	cookie := new(http.Cookie)
	cookie.Name = "refresh_token"
	cookie.Value = refreshToken
	cookie.HttpOnly = true
	cookie.Secure = false
	cookie.Path = "/"
	cookie.Expires = time.Now().Add(7 * 24 * time.Hour)
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, echo.Map{"access_token": accessToken})
}

func (h *AuthHandler) Refresh(c echo.Context) error {
	cookie, err := c.Cookie("refresh_token")
	if err != nil {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "refresh token missing"})
	}
	token, err := jwt.Parse(cookie.Value, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, echo.NewHTTPError(http.StatusUnauthorized, "unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid refresh token"})
	}

	claims := token.Claims.(jwt.MapClaims)
	username := claims["username"].(string)
	accessToken, err := generateAccessToken(username)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "token generation failed"})
	}

	return c.JSON(http.StatusOK, echo.Map{"access_token": accessToken})
}

func generateAccessToken(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func generateRefreshToken(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(7 * 24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func (h *AuthHandler) Protected(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	username := claims["username"].(string)
	return c.JSON(http.StatusOK, echo.Map{"message": "Welcome " + username})
}
