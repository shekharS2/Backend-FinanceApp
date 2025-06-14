package main

import (
	"context"
	// "net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/coder/websocket"
)


// how to encrypt chats?
// 

func WebSocketHandler(hub *Hub) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Upgrade connection
		conn, err := websocket.Accept(c.Response(), c.Request(), &websocket.AcceptOptions{
			OriginPatterns: []string{"*"},
		})
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(c.Request().Context(), time.Minute*10)
		defer cancel()

		client := &Client{
			Conn: conn,
			Send: make(chan []byte, 256),
			Hub:  hub,
		}

		hub.Register <- client

		go client.WriteLoop(ctx)
		client.ReadLoop(ctx)

		return nil
	}
}
