package txcore

// TX struct
type TX struct {
	Outputs []output // Public key of the output
	Inputs  []utxo

	RawTX       []byte
	SignedTX    []byte
	SignedTXHex string
}

type output struct {
	Base58Address string
	Amount        int
}

type utxo struct {
	TxID       string
	Index      int
	PublicKey  string
	Compressed bool
}
