package des

import (
  "testing"
  "crypto/block"
  "crypto/cipher"
  "bytes"
  "io"
)
func same(p, q []byte) bool {
  if len(p) != len(q) {
    return false
  }
  for i := 0; i < len(p); i++ {
    if p[i] != q[i] {
      return false
    }
  }
  return true
}

func genericDES (c block.Cipher, t *testing.T, tt cbcTest) {
  test := tt.name

  var crypt bytes.Buffer
  w := block.NewCBCEncrypter(c, tt.iv, &crypt)
  var r io.Reader = bytes.NewBuffer(tt.in)
  n,err := io.Copy(w,r)
  if n != int64(len(tt.in)) || err != nil {
    t.Errorf("%s: CBCEncrypter io.Copy = %d, %v want %d, nil", test, n, err, len(tt.in))
  } else if d := crypt.Bytes(); !same(tt.out, d) {
    t.Errorf("%s: CBCEncrypter\nhave %x\nwant %x", test, d, tt.out)
  }

  var plain bytes.Buffer
  r = block.NewCBCDecrypter(c, tt.iv, bytes.NewBuffer(tt.out))
  w = &plain
  n, err = io.Copy(w, r)
  if n != int64(len(tt.out)) || err != nil {
    t.Errorf("%s: CBCDecrypter io.Copy = %d, %v want %d, nil", test, n, err, len(tt.out))
  } else if d := plain.Bytes(); !same(tt.in, d) {
    t.Errorf("%s: CBCDecrypter\nhave %x\nwant %x", test, d, tt.in)
  }
}
func des (t *testing.T, tt cbcTest) {
  c, err := NewDESCipher(tt.key)
  if err != nil {
     t.Errorf("%s: NewCipher(%d bytes) = %s", tt.name, len(tt.key), err)
  } else {
    genericDES(c, t, tt)
  }
}
func des2 (t *testing.T, tt cbcTest) {
  c, err := NewDES2Cipher(tt.key)
  if err != nil {
     t.Errorf("%s: NewCipher(%d bytes) = %s", tt.name, len(tt.key), err)
  } else {
    genericDES(c, t, tt)
  }
}
func des3 (t *testing.T, tt cbcTest) {
  c, err := NewDES3Cipher(tt.key)
  if err != nil {
     t.Errorf("%s: NewCipher(%d bytes) = %s", tt.name, len(tt.key), err)
  } else {
    genericDES(c, t, tt)
  }
}
func TestCBC_DES (t *testing.T) {
  des (t, cbcDESTests[0])
  des2(t, cbcDESTests[1])
  des3(t, cbcDESTests[2])
}


// different tests

var cbcDES3Tests = []struct {
  key []byte
  iv  []byte
  in  []byte
  out []byte
}{
  {
    commonKey24,
    zeroIV8,
    []byte{1, 2, 3, 4, 5, 6, 7, 8},
    []byte{0x2e, 0xe4, 0xfc, 0x93, 0x96, 0x7, 0x7e, 0xd},
  },
}

func TestCBC_DES3(t *testing.T) {
  for _, tt := range cbcDES3Tests {
    c, err := NewDES3Cipher(tt.key)
    if err != nil {
      t.Errorf("NewDES3Cipher(%d bytes) = %s", len(tt.key), err)
      continue
    }

    encrypter := cipher.NewCBCEncrypter(c, tt.iv)
    d := make([]byte, len(tt.in))
    encrypter.CryptBlocks(d, tt.in)
    if !bytes.Equal(tt.out, d) {
      t.Errorf("CBCEncrypter\nhave %x\nwant %x", d, tt.out)
    }

    decrypter := cipher.NewCBCDecrypter(c, tt.iv)
    p := make([]byte, len(d))
    decrypter.CryptBlocks(p, d)
    if !bytes.Equal(tt.in, p) {
      t.Errorf("CBCDecrypter\nhave %x\nwant %x", p, tt.in)
    }
  }
}
