package main

import (
	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()
	hub := NewHub()

	go hub.Run()

	e.GET("/ws", WebSocketHandler(hub))

	e.Logger.Fatal(e.Start(":1323"))
}


// import (
// 	"net/http"
	
// 	"github.com/labstack/echo/v4"
// )

// func main() {
// 	e := echo.New()
// 	e.GET("/", func(c echo.Context) error {
// 		return c.String(http.StatusOK, "Hello, World!")
// 	})
// 	e.Logger.Fatal(e.Start(":1323"))
// }