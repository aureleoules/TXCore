package main

import (
	"log"
	"bytes"
	"encoding/hex"
	"errors"
	"encoding/binary"
	"strconv"
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

	/* Sign the transaction */
	signedTX, ok := signRaw(tx, privateKeys[0])
	if !ok {
		return errors.New("could not sign tx")
	}

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
func (tx *TX) AddInput(txHash string, publicKey string) error {
	// TODO clean this bullshit
	tx.Hash = txHash
	tx.PublicKey = publicKey
	return nil
}

// Build tx
func (tx *TX) Build() []byte {

	version, err := hex.DecodeString("01000000")
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

	if tx.ScriptSig == nil {
		tx.ScriptSig = buildPublicKeyScript(tx.PublicKey)
	}

	//Script sig length
	scriptSigLength := len(tx.ScriptSig)

	//sequence_no. Normally 0xFFFFFFFF. Always in this case.
	sequence, err := hex.DecodeString("ffffffff")
	if err != nil {
		log.Fatal(err)
	}

	//Numbers of outputs for the transaction being created.
	log.Println(strconv.Itoa(len(tx.Outputs)))
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
	buffer.Write(tx.ScriptSig)
	buffer.Write(sequence)
	buffer.Write(numOutputs)
	for _, output := range tx.Outputs {
		log.Println(output)
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

	return buffer.Bytes()
}

// NewTX return basic tx
func NewTX() TX {
	return TX{}
}

func main() {

}
