package des

import (
  "crypto/rand"
  "os"
)
const (
  odd =1
  even=0
)

func GenerateDESKey()  ([]byte, os.Error){
  return generateDESKey(8)
}
func GenerateDES2Key() ([]byte, os.Error){
  return generateDESKey(16)
}
func GenerateDES3Key() ([]byte, os.Error){
  return generateDESKey(24)
}

func generateDESKey(n int) ([]byte, os.Error){
  key := make([]byte, n)
  if r, err := rand.Read(key); nil!=err || r!=n {
    switch err {
      default : return nil, err
      case nil: return nil, KeySizeError(r)
    }
  }
  // fix parity
  for i,b := range(key) {
    if even == checkParityByte(b) {
      key[i] ^=  0x01
    }
  }
  return key, nil
}

func checkParityBytes(bytes []byte) (which int, ok bool){
  for i, b := range(bytes) {
    if even == checkParityByte(b) {
      return i, false
    }
  }
  return -1, true
}

// Functionality to check whether the parity
// of a byte is even or odd. I.e. whether a 
// byte contains an even or odd number of bits.
func checkParityByte(b byte) int {
  b = b ^ (b>>1)
  b = b ^ (b>>2)
  b = b ^ (b>>4)
  return int(b & 0x01)
}
