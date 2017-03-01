package main

import (
	"net/http"
	"time"

	"os"

	"crypto/rand"

	"fmt"

	"flag"

	"io"
	"io/ioutil"

	"crypto/tls"
	"log"
)

var (
	listen = flag.String("listen", ":5000", "Port to listen on")
)

func main() {
	server := &http.Server{
		Addr:         *listen,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}

	buf := make([]byte, 2048*2+17) //send 4113 bytes
	rand.Read(buf)
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(ioutil.Discard, r.Body)
		r.Body.Close()
		w.Write(buf)
	})

	/*pub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")
	priv, _ := base64.StdEncoding.DecodeString("vFilCT/FcyeShgbpTUrpru9n5yzZey8yfhsAx6DeL80=")

	serverKeys := noise.DHKey{
		Public:  pub,
		Private: priv,
	}*/

	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Println(err)
		return
	}

	l, err := tls.Listen("tcp", ":5000", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	//l, err := noisetls.Listen("tcp", ":5000", serverKeys)
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}
	// Close the listener when the application closes.
	defer l.Close()

	fmt.Println("Starting server...")
	if err := server.Serve(l); err != nil {
		panic(err)
	}

}
