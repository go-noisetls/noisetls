package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

func main() {

	t := time.Now()
	n := 10000
	buf := make([]byte, 20048+8)
	rand.Read(buf)
	c := make(chan bool, 10)

	threads := 10

	/*pub1, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")
	priv1, _ := base64.StdEncoding.DecodeString("vFilCT/FcyeShgbpTUrpru9n5yzZey8yfhsAx6DeL80=")

	serverPub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")

	clientKeys := noise.DHKey{
		Public:  pub1,
		Private: priv1,
	}*/

	transport := &http.Transport{
		MaxIdleConnsPerHost: threads,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		/*DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := noisetls.Dial(network, addr, clientKeys, serverPub)
			if err != nil {
				fmt.Println(err)
			}
			return conn, err
		},*/
	}
	for j := 0; j < threads; j++ {
		go func() {

			cli := &http.Client{
				Transport: transport,
			}
			for i := 0; i < n; i++ {
				reader := bytes.NewReader(buf)
				req, err := http.NewRequest("POST", "https://127.0.0.1:5000/", reader)
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
