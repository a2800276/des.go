

package des

type Cipher struct{
  enc [] uint32
  dec [] uint32
}

// This contains the necessary function to comply with the Cipher interface.


func NewCipher(key []byte) (*Cipher) {
  /* TODO sanity check, error handling, key parity */
  c := &Cipher{make([]uint32, 32), make([]uint32, 32)}
  deskey(key, c)
  return c
}

// BlockSize returns the cipher's block size.
func (c *Cipher) BlockSize() int {
  return 8
}

// Encrypt encrypts the first block in src into dst.
// Src and dst may point at the same memory.
func (c *Cipher) Encrypt(src, dst []byte) {
  desfunc(src, dst, c.enc)
}

// Decrypt decrypts the first block in src into dst.
// Src and dst may point at the same memory.
func (c *Cipher) Decrypt(src, dst []byte) {
  desfunc(src, dst, c.enc)
}

