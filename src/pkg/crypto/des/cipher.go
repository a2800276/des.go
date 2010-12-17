
package des

import (
  "os"
  "strconv"
)

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

type KeySizeError   int
type KeyParityError int

func (k KeySizeError)   String() string {
	return "crypto/des: invalid key size " + strconv.Itoa(int(k))
}
func (k KeyParityError) String() string {
	return "crypto/des: invalid key parity in byte " + strconv.Itoa(int(k))
}


// This contains the necessary function to comply with the Cipher interface.


func NewDESCipher(key []byte) (*DES, os.Error) {

  if nil == key || 8 != len(key) {
    return nil, KeySizeError(len(key))
  }

  if which, ok := checkParityBytes(key); ok != true {
    return nil, KeyParityError(which)
  }

  c := &DES{make([]uint32, 32), make([]uint32, 32)}
  deskey(key, c)

  return c, nil
}
func NewDES2Cipher(key []byte) (*DES2, os.Error) {
  if nil == key || 16 != len(key) {
    return nil, KeySizeError(len(key))
  }

  if des3, err := newDES3Cipher(key); err != nil {
    return nil, err
  } else {
    return &DES2{des3}, nil
  }
  // can't happen.
  // compiler "bug" complains about no return stmt.
  return nil, nil 
}

func NewDES3Cipher(key []byte) (*DES3, os.Error) {
   if nil == key || 24 != len(key) {
    return nil, KeySizeError(len(key))
  }

  return newDES3Cipher(key)
}

func newDES3Cipher(key []byte) (*DES3, os.Error) {

  var des  [3]*DES
  var keys [3][]byte

  // this creates both 2DES and 3DES ciphers,
  // key length & parity checks are performed in the
  // public methods.
  //
  // no sanity length checks, this is an internal method and will lead
  // to out-of-bounds in case it's abused internally.

  for i := range(keys) {
    switch (i) {
      case 0: keys[0] = key[0:8]
      case 1: keys[1] = key[8:16]
      case 2:
        if len(key) == 16 {
          keys[2] = keys[0]
        } else {
          keys[2] = key[16:]
        }
      // default panic?
    } //switch

    var err os.Error
    if des[i], err = NewDESCipher(keys[i]); err != nil {
      return nil, err
    }
  }

  return &DES3{des[0],des[1], des[2]}, nil

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
// Src and dst may point at the same memory, i.e. this
// function works in place, though you probably wouldn't
// use it directly anyhow.
func (c *DES) Encrypt(dst, src []byte) {
  desfunc(dst, src, c.enc)
}
func (c *DES3) Encrypt(dst, src []byte) {
  desfunc(dst, src, c.des1.enc)
  desfunc(dst, dst, c.des2.dec)
  desfunc(dst, dst, c.des3.enc)
}
func (c *DES2) Encrypt(dst, src []byte) {
  c.des3.Encrypt(dst, src)
}


// Decrypt decrypts the first block in src into dst.
// Src and dst may point at the same memory.
func (c *DES) Decrypt(dst, src []byte) {
  desfunc(dst, src, c.dec)
}
func (c *DES3) Decrypt(dst, src []byte) {
  desfunc(dst, src, c.des3.dec)
  desfunc(dst, dst, c.des2.enc)
  desfunc(dst, dst, c.des1.dec)
}

func (c *DES2) Decrypt(dst, src []byte) {
  c.des3.Decrypt(dst, src)
}

