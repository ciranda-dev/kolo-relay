package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolorelay "github.com/ciranda-dev/kolo-relay"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relayID, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	targetID, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	dialerID, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}

	relay, err := kolorelay.Listen(ctx, "127.0.0.1:0", relayID, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer relay.Close()
	addr, key := relay.Addr().String(), relayID.PublicKey()

	res, err := kolorelay.Reserve(ctx, addr, key, targetID, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Close()
	go func() {
		c, err := res.Accept(ctx)
		if err != nil {
			return
		}
		s, err := c.AcceptStream(ctx)
		if err != nil {
			return
		}
		io.Copy(s, s)
		s.Close()
	}()

	c, err := kolorelay.Dial(ctx, addr, key, dialerID, targetID.PublicKey(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	fmt.Printf("connected to %x through relay %x\n", c.RemotePublicKey()[:4], c.RelayPublicKey()[:4])
	s, err := c.OpenStream(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := s.Write([]byte("hello kolo")); err != nil {
		log.Fatal(err)
	}
	s.Close()
	reply, err := io.ReadAll(s)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", reply)
}
