package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/aureleoules/txcore/base58"
	secp256k1 "github.com/toxeus/go-secp256k1"
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

func signRaw(tx *TX, privateKey string) ([]byte, bool) {
	secp256k1.Start()
	decoded := decodeKey(privateKey)

	publicKeyBytes, ok := secp256k1.Pubkey_create(*byte32(decoded), tx.Compressed)
	if !ok {
		return nil, false
	}

	shaHash := sha256.New()
	shaHash.Write(tx.RawTX)
	var hash []byte = shaHash.Sum(nil)

	shaHash2 := sha256.New()
	shaHash2.Write(hash)
	rawTransactionHashed := shaHash2.Sum(nil)

	nounce := generateNonce()

	signedTransaction, ok := secp256k1.Sign(*byte32(rawTransactionHashed), *byte32(decoded), &nounce)
	if !ok {
		return nil, false
	}

	ok = secp256k1.Verify(*byte32(rawTransactionHashed), signedTransaction, publicKeyBytes)
	if !ok {
		return nil, false
	}

	secp256k1.Stop()

	hashCodeType, err := hex.DecodeString("01")
	if err != nil {
		log.Fatal(err)
	}

	signedTransactionLength := byte(len(signedTransaction) + 1)

	var buf bytes.Buffer
	buf.Write(publicKeyBytes)
	pubKeyLength := byte(len(buf.Bytes()))

	var buffer bytes.Buffer
	buffer.WriteByte(signedTransactionLength)
	buffer.Write(signedTransaction)
	buffer.WriteByte(hashCodeType[0])
	buffer.WriteByte(pubKeyLength)
	buffer.Write(buf.Bytes())

	scriptSig := buffer.Bytes()
	tx.ScriptSig = scriptSig

	return tx.Build(), true
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
