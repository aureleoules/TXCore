package main

import (
	"log"
	"bytes"
	"encoding/hex"
	"errors"
	"crypto/sha256"

	secp256k1 "github.com/toxeus/go-secp256k1"
)

// Sign tx
func (tx *TX) Sign(privateKeys []string) error {
	
	if len(privateKeys) != len(tx.Inputs) {
		return errors.New("missing private keys")
	}

	hashCodeType, err := hex.DecodeString("01000000")
	if err != nil {
		return err
	}
	
	var buf bytes.Buffer
	buf.Write(tx.RawTX)
	buf.Write(hashCodeType)
	tx.RawTX = buf.Bytes()
	
	var scriptSignatures [][]byte
	for i, input := range tx.Inputs {
	
		secp256k1.Start()
		decoded := decodeKey(privateKeys[i])
	
		publicKeyBytes, ok := secp256k1.Pubkey_create(*byte32(decoded), input.Compressed)
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
			return errors.New("could not sign")
		}
	
		ok = secp256k1.Verify(*byte32(rawTransactionHashed), signedTransaction, publicKeyBytes)
		if !ok {
			return errors.New("could not verify")
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

		log.Println(scriptSig)
		scriptSignatures = append(scriptSignatures, scriptSig)
		signedTX := buildRawTX(tx, scriptSignatures)
	
		/* Convert to hex */
		signedTXHex := hex.EncodeToString(signedTX)
	
		tx.SignedTX = signedTX
		tx.SignedTXHex = signedTXHex
	}


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
	input := utxo{
		TxID: txHash,
		PublicKey: publicKey,
		Index: utxoIndex,
		Compressed: compressed,
	}
	tx.Inputs = append(tx.Inputs, input)
	return nil
}

// Build tx
func (tx *TX) Build() []byte {
	rawTX := buildRawTX(tx, [][]byte{})
	tx.RawTX = rawTX
	return rawTX
}

// NewTX return basic tx
func NewTX() TX {
	return TX{}
}

func main() {

}
