package main

import (
	"log"
	"os"
)

func main() {
	if ip, err := lookupDomain(os.Args[1]); err != nil {
		log.Fatal(err)
	} else {
		log.Printf("IP: %v\n", ip)
	}
}
