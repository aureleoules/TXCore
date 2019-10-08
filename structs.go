package main


// TX struct
type TX struct {
	Outputs []output // Public key of the output
	Hash        string // UTXO ID
	PublicKey   string // Public key of the input
	Compressed  bool   // whether the PublicKey is compressed or not
	TxIndex     int    // the utxo output index

	ScriptSig []byte

	RawTX       []byte
	SignedTX    []byte
	SignedTXHex string
}

type output struct {
	Base58Address string
	Amount int
}