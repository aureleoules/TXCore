package main

import (
	"bytes"
	"encoding/hex"
	"github.com/aureleoules/txcore/base58"
	"log"
	"math"
	"math/rand"
	"time"
	"unsafe"
)

func decodeKey(value string) []byte {
	zeroBytes := 0
	for i := 0; i < len(value); i++ {
		if value[i] == 49 {
			zeroBytes++
		} else {
			break
		}
	}

	publicKeyInt, err := base58.DecodeToBig([]byte(value))
	if err != nil {
		log.Fatal(err)
	}

	encodedChecksum := publicKeyInt.Bytes()

	encoded := encodedChecksum[0 : len(encodedChecksum)-4]

	var buffer bytes.Buffer
	for i := 0; i < zeroBytes; i++ {
		zeroByte, err := hex.DecodeString("00")
		if err != nil {
			log.Fatal(err)
		}
		buffer.WriteByte(zeroByte[0])
	}

	buffer.Write(encoded)

	return buffer.Bytes()[1:len(buffer.Bytes())]
}

func generateNonce() [32]byte {
	var bytes [32]byte
	for i := 0; i < 32; i++ {
		bytes[i] = byte(randInt(0, math.MaxUint8))
	}
	return bytes
}

func randInt(min int, max int) uint8 {
	rand.Seed(time.Now().UTC().UnixNano())
	return uint8(min + rand.Intn(max-min))
}

func buildPublicKeyScript(publicKey string) []byte {
	publicKeyBytes := decodeKey(publicKey)

	var scriptPubKey bytes.Buffer
	scriptPubKey.WriteByte(byte(118))
	scriptPubKey.WriteByte(byte(169))
	scriptPubKey.WriteByte(byte(len(publicKeyBytes)))
	scriptPubKey.Write(publicKeyBytes)
	scriptPubKey.WriteByte(byte(136))
	scriptPubKey.WriteByte(byte(172))
	return scriptPubKey.Bytes()
}

// Converts a byte slice to a 32 byte slice
func byte32(s []byte) (a *[32]byte) {
	if len(a) <= len(s) {
		a = (*[len(a)]byte)(unsafe.Pointer(&s[0]))
	}
	return a
}
