package main

import (
	"log"
	"bytes"
	"encoding/hex"
	"errors"
	"encoding/binary"
	"strconv"
	"crypto/sha256"

	secp256k1 "github.com/toxeus/go-secp256k1"
)

// Sign tx
func (tx *TX) Sign(privateKeys []string) error {
	hashCodeType, err := hex.DecodeString("01000000")
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	buf.Write(tx.RawTX)
	buf.Write(hashCodeType)
	tx.RawTX = buf.Bytes()

	secp256k1.Start()
	decoded := decodeKey(privateKeys[0])

	publicKeyBytes, ok := secp256k1.Pubkey_create(*byte32(decoded), tx.Compressed)
	if !ok {
		return errors.New("could not create public key")
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
		return errors.New("could not create sign")
	}

	ok = secp256k1.Verify(*byte32(rawTransactionHashed), signedTransaction, publicKeyBytes)
	if !ok {
		return errors.New("could not create verify")
	}

	secp256k1.Stop()

	hashCodeTypeHex, err := hex.DecodeString("01")
	if err != nil {
		log.Fatal(err)
	}

	signedTransactionLength := byte(len(signedTransaction) + 1)

	var buf2 bytes.Buffer
	buf2.Write(publicKeyBytes)
	pubKeyLength := byte(len(buf2.Bytes()))

	var buffer bytes.Buffer
	buffer.WriteByte(signedTransactionLength)
	buffer.Write(signedTransaction)
	buffer.WriteByte(hashCodeTypeHex[0])
	buffer.WriteByte(pubKeyLength)
	buffer.Write(buf2.Bytes())

	scriptSig := buffer.Bytes()

	signedTX := tx.Build(scriptSig)
	
	/* Convert to hex */
	signedTXHex := hex.EncodeToString(signedTX)

	tx.SignedTX = signedTX
	tx.SignedTXHex = signedTXHex

	return nil
}

// AddOutput to the tx
func (tx *TX) AddOutput(base58address string, amount int) error {
	tx.Outputs = append(tx.Outputs, output{
		Base58Address: base58address, 
		Amount: amount,
	})
	return nil
}

// AddInput to the tx
func (tx *TX) AddInput(txHash string, publicKey string, utxoIndex int, compressed bool) error {
	// TODO clean this bullshit
	tx.Hash = txHash
	tx.PublicKey = publicKey
	tx.TxIndex = utxoIndex
	tx.Compressed = compressed
	return nil
}

// Build tx
func (tx *TX) Build(scriptSig []byte) []byte {

	version, err := hex.DecodeString("02000000")
	if err != nil {
		log.Fatal(err)
	}

	inputs, err := hex.DecodeString("01")
	if err != nil {
		log.Fatal(err)
	}

	inputTransactionBytes, err := hex.DecodeString(tx.Hash)
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
	binary.LittleEndian.PutUint32(outputIndexBytes, uint32(tx.TxIndex))

	//Script sig length
	scriptSigLength := len(scriptSig)

	//sequence_no. Normally 0xFFFFFFFF. Always in this case.
	sequence, err := hex.DecodeString("ffffffff")
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
	buffer.Write(inputTransactionBytesReversed)
	buffer.Write(outputIndexBytes)
	buffer.WriteByte(byte(scriptSigLength))
	buffer.Write(scriptSig)
	buffer.Write(sequence)
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

	rawTX := buffer.Bytes()
	tx.RawTX = rawTX
	return rawTX
}

// NewTX return basic tx
func NewTX() TX {
	return TX{}
}

func main() {

}
