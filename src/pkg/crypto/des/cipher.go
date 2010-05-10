

package des

type DES struct{
  enc [] uint32
  dec [] uint32
}

type DES2 struct {
  des3 *DES3
}

type DES3 struct {
  des1, des2, des3 *DES
}

// This contains the necessary function to comply with the Cipher interface.


func NewDESCipher(key []byte) (*DES) {
  /* TODO sanity check, error handling, key parity */
  c := &DES{make([]uint32, 32), make([]uint32, 32)}
  deskey(key, c)
  return c
}
func NewDES2Cipher(key []byte) (*DES2) {
  des3 := newDES3Cipher(key)
  return &DES2{des3}
}

func NewDES3Cipher(key []byte) (*DES3) {
  return newDES3Cipher(key)
}

func newDES3Cipher(key []byte) (*DES3) {
  // this creates both 2DES and 3DES ciphers,
  // key length & parity checks are performed in the
  // public methods.
  c1:=NewDESCipher(key[0:8])
  c2:=NewDESCipher(key[8:16])
  var c3 *DES
  if len(key) > 16 {
    c3=NewDESCipher(key[16:])
  } else {
    c3=NewDESCipher(key[0:8])
  }

  return &DES3{c1,c2,c3}

}


// BlockSize returns the cipher's block size.
func (c *DES) BlockSize() int {
  return 8
}
func (c *DES2) BlockSize() int {
  return 8
}
func (c *DES3) BlockSize() int {
  return 8
}

// Encrypt encrypts the first block in src into dst.
// Src and dst may point at the same memory.
func (c *DES) Encrypt(src, dst []byte) {
  desfunc(src, dst, c.enc)
}
func (c *DES3) Encrypt(src, dst []byte) {
  desfunc(src, dst, c.des1.enc)
  desfunc(dst, dst, c.des2.dec)
  desfunc(dst, dst, c.des3.enc)
}
func (c *DES2) Encrypt(src, dst []byte) {
  c.des3.Encrypt(src, dst)
}


// Decrypt decrypts the first block in src into dst.
// Src and dst may point at the same memory.
func (c *DES) Decrypt(src, dst []byte) {
  desfunc(src, dst, c.dec)
}
func (c *DES3) Decrypt(src, dst []byte) {
  desfunc(src, dst, c.des3.dec)
  desfunc(dst, dst, c.des2.enc)
  desfunc(dst, dst, c.des1.dec)
}

func (c *DES2) Decrypt(src, dst []byte) {
  c.des3.Decrypt(src, dst)
}

