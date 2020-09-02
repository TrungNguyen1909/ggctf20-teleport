package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	http.HandleFunc("/iframe", func(w http.ResponseWriter, _ *http.Request) {
		// if len(c.Request().Header.Get("Service-Worker-Navigation-Preload")) <= 0 {
		// 	log.Println("Not a preload")
		// }
		time.Sleep(10 * time.Second)
		w.Write([]byte{0x41, 0x42, 0x43, 0x44})
	})

	http.HandleFunc("/pwned", func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		log.Printf("Pwned! %s", body)
	})
	http.HandleFunc("/failed", func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		log.Printf("FAIL: %s", body)
	})
	http.Handle("/", http.FileServer(http.Dir(".")))
	log.Println("Starting server...")
	// log.Fatal(http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil))
	port, ok := os.LookupEnv("PORT")
	if !ok {
		port = "8888"
	}
	port = ":" + port
	log.Fatal(http.ListenAndServe(port, nil))
}
