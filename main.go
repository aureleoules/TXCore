package main

import (
	"bytes"
	"encoding/hex"
	"errors"
)

// TX struct
type TX struct {
	Destination string // Public key of the output
	Amount      int    // Amount in satoshis
	Hash        string // UTXO ID
	PublicKey   string // Public key of the input
	Compressed  bool   // whether the PublicKey is compressed or not
	TxIndex     int    // the utxo output index

	RawTX       []byte
	SignedTX    []byte
	SignedTXHex string
}

// BuildRawTX constructs a raw bitcoin transaction
func BuildRawTX(destination string, amount int, txHash string, publicKey string, compressed bool) TX {
	rawTx := buildRawTransaction(txHash, 0, destination, amount, buildPublicKeyScript(publicKey))

	return TX{
		Amount:      amount,
		Destination: destination,
		Hash:        txHash,
		PublicKey:   publicKey,
		Compressed:  compressed,
		RawTX:       rawTx,
	}
}

// Sign tx
func (tx *TX) Sign(privateKey string) error {
	hashCodeType, err := hex.DecodeString("01000000")
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	buf.Write(tx.RawTX)
	buf.Write(hashCodeType)
	tx.RawTX = buf.Bytes()

	/* Sign the transaction */
	signedTX, ok := signRaw(tx, privateKey)
	if !ok {
		return errors.New("could not sign tx")
	}

	/* Convert to hex */
	signedTXHex := hex.EncodeToString(signedTX)

	tx.SignedTX = signedTX
	tx.SignedTXHex = signedTXHex

	return nil
}

func main() {

}
