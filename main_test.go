package txcore

import (
	"log"
	"testing"
)

func TestMain(t *testing.T) {

	tx := NewTX()

	tx.AddInput("cb6d7af6c274d2671aab7e5eb084d59e37f622248563aec64e2da67c7ec29ec2", "mz8NhsSzRXKx66GZRqf2a62iMBN6PqxbwH", 0, true)
	tx.AddInput("e89dcfeafc949aaccb47eac98f0efc59e47d135ce15548cc10ba6c9ff1fb6d67", "mgWptdrUwFFoazVCkC85XGNviwmSkTpt63", 0, true)

	total := 7226645 + 2163269

	tx.AddOutput("mz8NhsSzRXKx66GZRqf2a62iMBN6PqxbwH", total-6000)
	tx.AddOutput("mqMt69dhDW3qgaaqhxM3UPEyfisdAgiJ7J", 5000)

	tx.Build()
	err := tx.Sign([]string{"cQcNmeNmiXysYJT2cGFxYqkh4a3TCniDa25SGvnJJvXmA8DtDJtF", "cR3gEoxMV25dPAJmBjVidahbTdYZVtHjDjBLasgU5q9kDdxxkins"})
	if err != nil {
		log.Fatalln(err)
	}

	log.Println(tx.SignedTXHex)

}
