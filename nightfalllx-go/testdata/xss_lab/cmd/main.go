package main

import (
	"fmt"
	"log"
	"net/http"
	"nightfalllx/testdata/xss_lab"
)

func main() {
	mux := xsslab.SetupMux()
	addr := "127.0.0.1:8888"
	fmt.Printf("[*] NightfallLX XSS Lab Server listening at http://%s\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
