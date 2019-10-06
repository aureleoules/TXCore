package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
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

	return buildRawTransaction(tx.Hash, 0, tx.Destination, tx.Amount, scriptSig), true
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

func buildRawTransaction(inputTransactionHash string, inputTransactionIndex int, publicKeyBase58Destination string, satoshis int, scriptSig []byte) []byte {

	version, err := hex.DecodeString("01000000")
	if err != nil {
		log.Fatal(err)
	}

	inputs, err := hex.DecodeString("01")
	if err != nil {
		log.Fatal(err)
	}

	inputTransactionBytes, err := hex.DecodeString(inputTransactionHash)
	if err != nil {
		log.Fatal(err)
	}

	//Convert input transaction hash to little-endian form
	inputTransactionBytesReversed := make([]byte, len(inputTransactionBytes))
	for i := 0; i < len(inputTransactionBytes); i++ {
		inputTransactionBytesReversed[i] = inputTransactionBytes[len(inputTransactionBytes)-i-1]
	}

	//Output index of input transaction
	outputIndexBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(outputIndexBytes, uint32(inputTransactionIndex))

	//Script sig length
	scriptSigLength := len(scriptSig)

	//sequence_no. Normally 0xFFFFFFFF. Always in this case.
	sequence, err := hex.DecodeString("ffffffff")
	if err != nil {
		log.Fatal(err)
	}

	//Numbers of outputs for the transaction being created. Always one in this example.
	numOutputs, err := hex.DecodeString("01")
	if err != nil {
		log.Fatal(err)
	}

	//Satoshis to send.
	satoshiBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(satoshiBytes, uint64(satoshis))

	//Script pub key
	scriptPubKey := buildPublicKeyScript(publicKeyBase58Destination)
	scriptPubKeyLength := len(scriptPubKey)

	//Lock time field
	lockTimeField, err := hex.DecodeString("00000000")
	if err != nil {
		log.Fatal(err)
	}

	var buffer bytes.Buffer
	buffer.Write(version)
	buffer.Write(inputs)
	buffer.Write(inputTransactionBytesReversed)
	buffer.Write(outputIndexBytes)
	buffer.WriteByte(byte(scriptSigLength))
	buffer.Write(scriptSig)
	buffer.Write(sequence)
	buffer.Write(numOutputs)
	buffer.Write(satoshiBytes)
	buffer.WriteByte(byte(scriptPubKeyLength))
	buffer.Write(scriptPubKey)
	buffer.Write(lockTimeField)

	return buffer.Bytes()
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
