package txcore

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"github.com/aureleoules/txcore/base58"
	"log"
	"math"
	"math/rand"
	"strconv"
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

func buildRawTX(tx *TX, scriptSigs [][]byte) []byte {
	version, err := hex.DecodeString("02000000")
	if err != nil {
		log.Fatal(err)
	}

	inputs, err := hex.DecodeString("0" + strconv.Itoa(len(tx.Inputs)))
	if err != nil {
		log.Fatal(err)
	}

	//Numbers of outputs for the transaction being created.
	numOutputs, err := hex.DecodeString("0" + strconv.Itoa(len(tx.Outputs)))
	if err != nil {
		log.Fatal(err)
	}

	//Lock time field
	lockTimeField, err := hex.DecodeString("00000000")
	if err != nil {
		log.Fatal(err)
	}
	var buffer bytes.Buffer
	buffer.Write(version)
	buffer.Write(inputs)

	for i, input := range tx.Inputs {
		var scriptSig []byte
		if len(scriptSigs) == 0 {
			log.Println("scriptSignatures = 0")
			scriptSig = buildPublicKeyScript(input.PublicKey)
		} else if i > len(scriptSigs)-1 {
			scriptSig = scriptSigs[i-1]
		} else {
			scriptSig = scriptSigs[i]
		}

		//Script sig length
		scriptSigLength := len(scriptSig)

		//sequence_no. Normally 0xFFFFFFFF. Always in this case.
		sequence, err := hex.DecodeString("ffffffff")
		if err != nil {
			log.Fatal(err)
		}

		inputTransactionBytes, err := hex.DecodeString(input.TxID)
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
		binary.LittleEndian.PutUint32(outputIndexBytes, uint32(input.Index))

		buffer.Write(inputTransactionBytesReversed)
		buffer.Write(outputIndexBytes)
		buffer.WriteByte(byte(scriptSigLength))
		buffer.Write(scriptSig)
		buffer.Write(sequence)
	}

	buffer.Write(numOutputs)

	for _, output := range tx.Outputs {
		//Satoshis to send.
		satoshiBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(satoshiBytes, uint64(output.Amount))

		//Script pub key
		scriptPubKey := buildPublicKeyScript(output.Base58Address)
		scriptPubKeyLength := len(scriptPubKey)

		buffer.Write(satoshiBytes)
		buffer.WriteByte(byte(scriptPubKeyLength))
		buffer.Write(scriptPubKey)
	}
	buffer.Write(lockTimeField)

	tx.RawTX = buffer.Bytes()
	return buffer.Bytes()
}
