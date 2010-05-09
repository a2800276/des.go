package des

import (
  "testing"
  "fmt"
)

/*
 * Single-length key, single-length plaintext -
 * Key    : 0123 4567 89ab cdef
 * Plain  : 0123 4567 89ab cde7
 * Cipher : c957 4425 6a5e d31d
*/

var (
  key   = []byte {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
  plain = []byte {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xe7}
  ciphr = []byte {0xc9, 0x57, 0x44, 0x25, 0x6a, 0x5e, 0xd3, 0x1d}
)

func TestEnc(t *testing.T){
  c := NewCipher(key)
  result := make([]byte,8)
  c.Encrypt(plain, result)
  for _,b := range result {
    fmt.Printf("%X ", b)
  }
}
func TestDec(t *testing.T){}





