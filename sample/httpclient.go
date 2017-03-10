package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/flynn/noise"
	"gopkg.in/noisetls.v0"
)

func main() {

	t := time.Now()
	n := 10000
	buf := make([]byte, 55)
	rand.Read(buf)
	c := make(chan bool, 10)

	threads := 2

	pub1, _ := base64.StdEncoding.DecodeString("L9Xm5qy17ZZ6rBMd1Dsn5iZOyS7vUVhYK+zby1nJPEE=")
	priv1, _ := base64.StdEncoding.DecodeString("TPmwb3vTEgrA3oq6PoGEzH5hT91IDXGC9qEMc8ksRiw=")

	serverPub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")

	clientKeys := noise.DHKey{
		Public:  pub1,
		Private: priv1,
	}

	payload := []byte(`{json:yes}111`)

	transport := &http.Transport{
		MaxIdleConnsPerHost: threads,
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := noisetls.Dial(network, addr, clientKeys, serverPub, payload)
			if err != nil {
				fmt.Println(err)
			}
			return conn, err
		},
	}
	for j := 0; j < threads; j++ {
		go func() {

			cli := &http.Client{
				Transport: transport,
			}
			for i := 0; i < n; i++ {
				reader := bytes.NewReader(buf)
				req, err := http.NewRequest("POST", "https://127.0.0.1:12888/", reader)
				if err != nil {
					panic(err)
				}

				resp, err := cli.Do(req)
				if err != nil {
					panic(err)
				}
				_, err = io.Copy(ioutil.Discard, resp.Body)

				if err != nil {
					panic(err)
				}
				err = resp.Body.Close()
				if err != nil {
					panic(err)
				}
			}
			c <- true
		}()
	}

	for j := 0; j < threads; j++ {
		<-c
	}
	fmt.Println(time.Since(t).Seconds())
}
