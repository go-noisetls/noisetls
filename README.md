# noisetls

go get -u gopkg.in/noisetls.v0

This is a plug-n-play replacement of TLS with noiseprotocol.org for Golang.

It is very early stage and experimental, but works.
Uses NoiseIK for now. No re-handshaking. 

#Packet structure (Big endian)
* Version uint 16
* Type uint16
* Size uint16
* Reserved uint16
* Payload [Size] bytes
