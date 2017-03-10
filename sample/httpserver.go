package main

import (
	"net/http"
	"time"

	"os"

	"crypto/rand"

	"fmt"

	"flag"

	"encoding/base64"
	"io"
	"io/ioutil"

	"log"

	"github.com/flynn/noise"
	"gopkg.in/noisetls.v0"
)

var (
	listen = flag.String("listen", ":5000", "Port to listen on")
)

func main() {

	go startHttpServer()
	startNoiseTLSServer()

}

func startNoiseTLSServer() {
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

	pub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")
	priv, _ := base64.StdEncoding.DecodeString("vFilCT/FcyeShgbpTUrpru9n5yzZey8yfhsAx6DeL80=")

	serverKeys := noise.DHKey{
		Public:  pub,
		Private: priv,
	}

	payload := []byte(`{json:yesyes}`)

	l, err := noisetls.Listen("tcp", ":12888", serverKeys, payload)
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

func sayhelloName(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h1 style="text-align: center;">Welcome to the Noise Socket demo!<br /><br />The server itself runs on port 12888</h1>
<p>&nbsp;</p>
<h2 style="text-align: center;">Server public key is&nbsp;</h2>
<h2 style="text-align: center;">J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=</h2>
<p>&nbsp;</p>
<h3>Supported ciphersuites:</h3>
<ul>
<li>Noise_XX_25519_AESGCM_SHA256<br />Noise_XX_25519_AESGCM_BLAKE2b<br />Noise_XX_25519_AESGCM_SHA512<br />Noise_XX_25519_AESGCM_BLAKE2s<br />Noise_XX_25519_ChaChaPoly_SHA256<br />Noise_XX_25519_ChaChaPoly_BLAKE2b<br />Noise_XX_25519_ChaChaPoly_SHA512<br />Noise_XX_25519_ChaChaPoly_BLAKE2s<br />Noise_IK_25519_AESGCM_SHA256<br />Noise_IK_25519_AESGCM_BLAKE2b<br />Noise_IK_25519_AESGCM_SHA512<br />Noise_IK_25519_AESGCM_BLAKE2s<br />Noise_IK_25519_ChaChaPoly_SHA256<br />Noise_IK_25519_ChaChaPoly_BLAKE2b<br />Noise_IK_25519_ChaChaPoly_SHA512<br />Noise_IK_25519_ChaChaPoly_BLAKE2s</li>
</ul>
<pre>&nbsp;</pre>`)
}

func startHttpServer() {
	http.HandleFunc("/", sayhelloName)     // set router
	err := http.ListenAndServe(":80", nil) // set listen port
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
