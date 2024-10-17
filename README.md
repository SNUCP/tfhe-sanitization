# Practical Sanitization for TFHE

Supplementary code for "Practical Sanitization for TFHE", based on [TFHE-go](https://github.com/sp301415/tfhe-go).
Go 1.18+ is required to run this code.

## Running Tests

You can run tests using standard Go testing tool:
```
$ go test .
```
This runs sanitization on 100 random ciphertexts.

## Benchmarking

You can also benchmark the base TFHE bootstrapping, our sanitization algorithm, and soak-spin-repeat sanitization using standard Go benchmark tool:
```
$ go test . -run=^$ -bench=.
```
