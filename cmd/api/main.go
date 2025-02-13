package main

import (
	"fmt"
	"log"
	"vuln-scanner/internal/server"

	_ "github.com/mattn/go-sqlite3"
)

// serverAddress is the address the server listens on
// In a production environment, this should be config driven
const serverAddress string = ":8080"

func main() {
	server, err := server.NewServer(serverAddress)
	if err != nil {
		log.Fatalf("Failed to create the server. err: %v", err)
	}

	log.Println(fmt.Sprintf("Starting the server on %s", serverAddress))

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start the server. err: %v", err)
	}
}
