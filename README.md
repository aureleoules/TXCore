<div align="center">
    <br>
    <a href="https://github.com/aureleoules/txcore"><img src="https://i.imgur.com/f2tekH1.png" alt="TXCore" width="250"></a>
    <br>
    <h1>TXCore</h1>
    <p align="center">The missing lightweight Bitcoin TX builder written in Go</p>
    <br>
</div>
    
## Usage

```go
    tx := txcore.NewTX()

    tx.AddInput("TxId", "Base58Address", outputIndex, isCompressed)
    tx.AddInput("TxId2", "AnotherBase58Address", output2Index, isCompressed)
    ...

    tx.AddOutput("abc", 100_000_000) // send one bitcoin to abc
    tx.AddOutput("xyz", 300_000_000) // send three bitcoins to xyz
    ...

    // Build raw tx
    tx.Build()

    // Sign with the corresponding private keys
    tx.Sign([]string{"privateKey1", "privateKey2", ...})

    // Print signed tx
    fmt.Println(tx.SignedTXHex)
```

## License
MIT