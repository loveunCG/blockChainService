package ethhash

import (
  "fmt"
  "io/ioutil"
  "encoding/hex"
  "github.com/ethereum/go-ethereum/crypto"
)

var KeccakStrength int // 256 or 512

// func CalcSha3FromByte(dat []byte) int {
func KeccakByte(data []byte, strength int) string { // Calculate HASH SHA3 from a []byte
  if strength == 512 {
    return hex.EncodeToString( crypto.Keccak512(data) )
  } else { // strength == 256
    return hex.EncodeToString( crypto.Keccak256(data) )
  }
}

// func CalcSha3(path string) int {
func KeccakFile( path string, strength int) string { // Calculate HASH SHA3 of a file in memory
	data, err := ioutil.ReadFile(path)
	dealwithErr(err)
    return KeccakByte(data, strength)
}

func dealwithErr(err error) {
  if err != nil {
    fmt.Println(err)
    panic(err)
  }
}
