package main

import (
	api_sec "f5_apisec_home_assignment/pkg"
	"log"
	"net/http"
)

func main() {
	// Set up the server routes
	http.Handle("/register", api_sec.Logger(http.HandlerFunc(api_sec.Register)))
	http.Handle("/login", api_sec.Logger(http.HandlerFunc(api_sec.Login)))
	// accounts and balance do need token authorization
	http.Handle("/accounts", api_sec.Logger(api_sec.Auth(api_sec.AccountsHandler)))
	http.Handle("/balance", api_sec.Logger(api_sec.Auth(api_sec.BalanceHandler)))

	// Define the server address and port
	addr := ":8080"

	// Start the server
	log.Println("Starting server on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
