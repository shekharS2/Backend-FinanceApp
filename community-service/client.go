package main

import (
	"context"
	"log"
	// "time"
	"github.com/coder/websocket"

)

type Client struct {
	Conn *websocket.Conn
	Send chan []byte
	Hub  *Hub
}

func (c *Client) ReadLoop(ctx context.Context) {
	defer func() {
		c.Hub.Unregister <- c
		c.Conn.Close(websocket.StatusNormalClosure, "read done")
	}()

	for {
		_, msg, err := c.Conn.Read(ctx)
		if err != nil {
			break
		}
		c.Hub.Broadcast <- msg
	}
}

func (c *Client) WriteLoop(ctx context.Context) {
	defer c.Conn.Close(websocket.StatusNormalClosure, "write done")

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-c.Send:
			if !ok {
				// Channel closed
				c.Conn.Close(websocket.StatusInternalError, "hub closed")
				return
			}
			err := c.Conn.Write(ctx, websocket.MessageText, msg)
			if err != nil {
				log.Println("write error:", err)
				return
			}
		}
	}
}
