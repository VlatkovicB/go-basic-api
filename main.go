package main

import (
	"log"
	"os"
)

func main() {
	os.Setenv("HMAC_SECRET", "randomsecret")
	store, err := NewPostgresStore()

	if err != nil {
		log.Fatal(err)
	}

	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	server := NewAPIServer(":3000", store)
	server.Run()
}
