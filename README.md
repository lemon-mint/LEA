# LEA

[![Go Reference](https://pkg.go.dev/badge/github.com/lemon-mint/LEA/golea.svg)](https://pkg.go.dev/github.com/lemon-mint/LEA/golea)

Pure Go implementation of `Lightweight Encryption Algorithm (LEA)`

The `golea` module uses the standard `cipher.Block` interface.
Just replace `aes` with `golea` and it works.

# Supported Algorithm

LEA-128, LEA-192, LEA-256

| Algorithm | Encryption | Decryption |
|-----------|------------|------------|
|LEA-128|Supported|Supported|
|LEA-192|Supported|Supported|
|LEA-256|Supported|Supported|
