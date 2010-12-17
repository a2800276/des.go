package des

import (
  "testing"
  //"fmt"
  "crypto/subtle"
  "crypto/block"
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

  key2  = []byte {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
  ciphr2= []byte {0x7f, 0x1d, 0x0a, 0x77, 0x82, 0x6b, 0x8a, 0xff}

  key3  = []byte {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67}
  ciphr3= []byte {0xde, 0x0b, 0x7c, 0x06, 0xae, 0x5e, 0x0e, 0xd5}


  key_parity_error = []byte {0x01, 0x23, 0x45, 0x67, 0x89, 0xac, 0xcd, 0xef}


  oddParityBytes = []byte {0x01, 0x02, 0x04, 0x07, 0xfe}
  evenParityBytes = []byte {0x00, 0x03, 0x05, 0x06, 0xff}

  // Bulk Tests
  //des1keys = [][]byte{}
  //plainTextBlocks = [][]byte{}
  //des1ciphers = [][][]byte{}
 

)

func TestEnc(t *testing.T){
  c, _ := NewDESCipher(key)
  result := make([]byte,8)
  c.Encrypt(result, plain)

  if 1 != subtle.ConstantTimeCompare(result,ciphr) {
    t.Errorf("1 DES Enc failed.")
  }

  c2,_ := NewDES2Cipher(key2)
  c2.Encrypt(result, plain)

  if 1 != subtle.ConstantTimeCompare(result,ciphr2) {
    t.Errorf("2 DES Enc failed.")
  }

  c3,_ := NewDES3Cipher(key3)
  c3.Encrypt(result, plain)

  if 1 != subtle.ConstantTimeCompare(result,ciphr3) {
    t.Errorf("3 DES Enc failed.")
  }
}

// fairly braindead stress test, just to make sure ...
func TestEncBulk(t *testing.T) {
  for i, key := range(des1keys) {
    if cipher, err := NewDESCipher(key); nil == err {
        testEncBulk(t, i, cipher, des1ciphers)
    } else {
      t.Errorf("1 DES #%d failed with err: %s", i, err)
    }
  }

  for i, key := range(des2keys) {
    if cipher, err := NewDES2Cipher(key); nil == err {
      testEncBulk(t, i, cipher, des2ciphers)
    } else {
      t.Errorf("2 DES #%d failed with err: %s", i, err)
    }
  }
  // yes, generics WOULD be nice...
  for i, key := range(des3keys) {
    if cipher, err := NewDES3Cipher(key); nil == err {
      testEncBulk(t, i, cipher, des3ciphers)
    } else {
      t.Errorf("3 DES #%d failed with err: %s", i, err)
    }
  }
}

// fairly braindead stress test, just to make sure ...
func TestDecBulk(t *testing.T) {
  for i, key := range(des1keys) {
    if cipher, err := NewDESCipher(key); nil == err {
        testDecBulk(t, i, cipher, des1ciphers)
    } else {
      t.Errorf("1 DES #%d failed with err: %s", i, err)
    }
  }
  for i, key := range(des2keys) {
    if cipher, err := NewDES2Cipher(key); nil == err {
      testDecBulk(t, i, cipher, des2ciphers)
    } else {
      t.Errorf("2 DES #%d failed with err: %s", i, err)
    }
  }
  // yes, generics WOULD be nice...
  for i, key := range(des3keys) {
    if cipher, err := NewDES3Cipher(key); nil == err {
      testDecBulk(t, i, cipher, des3ciphers)
    } else {
      t.Errorf("3 DES #%d failed with err: %s", i, err)
    }
  }

}


func testEncBulk(t *testing.T, kIdx int, cipher block.Cipher, cipherTexts [][][]byte) {
  result := make([]byte,8)
  for j, plain := range(plainTextBlocks) {
    cipher.Encrypt(result, plain)
    if 1 != subtle.ConstantTimeCompare(result, cipherTexts[j][kIdx]) {
      t.Errorf("? DES #%d encryption failed with plaintext #%d", j, kIdx)
    }
  }
}

func testDecBulk(t *testing.T, kIdx int, cipher block.Cipher, cipherTexts [][][]byte) {
  result := make([]byte,8)
  for j, plain := range(plainTextBlocks) {
    cipher.Decrypt(result, cipherTexts[j][kIdx])
    if 1 != subtle.ConstantTimeCompare(result, plain) {
      t.Errorf("? DES #%d decrypt failed with plaintext #%d", j, kIdx)
    }
  }
}


func TestDec(t *testing.T){
  c, _ := NewDESCipher(key)
  result := make([]byte,8)
  c.Decrypt(result, ciphr)

  if 1 != subtle.ConstantTimeCompare(result,plain) {
    t.Errorf("1 DES Dec failed.")
  }

  c2,_ := NewDES2Cipher(key2)
  c2.Decrypt(result, ciphr2)

  if 1 != subtle.ConstantTimeCompare(result,plain) {
    t.Errorf("2 DES Dec failed.")
  }

  c3,_ := NewDES3Cipher(key3)
  c3.Decrypt(result, ciphr3)

  if 1 != subtle.ConstantTimeCompare(result,plain) {
    t.Errorf("3 DES Dec failed.")
  }
}


func TestDec3IsNonMutating (t *testing.T){
  c3,_ := NewDES3Cipher(key3)
  enc := make([]byte,8)
  copy(enc, ciphr3)
  result := make([]byte,8)
  c3.Decrypt(result, enc)

  if 1 != subtle.ConstantTimeCompare(enc,ciphr3) {
    t.Errorf("3 DES Dec mutated the cipher string")
  }
}


func TestSanity (t *testing.T) {
  if _, error := NewDESCipher(nil); error == nil {
    t.Errorf("nil key should result in error")
  }
  // key too short
  if _, error := NewDESCipher(oddParityBytes); error == nil {
    t.Errorf("Incorrect key length should result in error")
  }

  // key des2 too long
  if _,error := NewDES2Cipher(key3); error == nil {
    t.Errorf("Incorrect key length should result in error, key too long for 2DES")
  }

  if _, error := NewDESCipher(key_parity_error); error == nil {
    t.Errorf("Incorrect key length should result in error, was (%d) should be 5", error)
  }

}

func TestParity (t *testing.T) {
 
  for _, b := range(oddParityBytes) {
    if odd != checkParityByte(b) {
      t.Errorf("Parity of %X should be odd!", b)
    }
  }

  for _, b := range(evenParityBytes) {
    if even != checkParityByte(b) {
      t.Errorf("Parity of %X should be even!", b)
    }
  }
}


func TestGenerateKey (t *testing.T) {
  for i:=0; i!=1000; i++ {
    // 1DES
    if key, err := GenerateDESKey(); err != nil {
      t.Errorf("Error generating key!")
    } else {
      if 8 != len(key) {
        t.Errorf("Wrong key length for generated 1DES key: %d", len(key));
      }

      if _, ok := checkParityBytes(key); ok != true {
        t.Errorf(" 1DES Key with incorrect parity generated!")
      }
    } // else

    // 2DES
    if key, err := GenerateDES2Key(); err != nil {
      t.Errorf("Error generating key!")
    } else {
      if 16 != len(key) {
        t.Errorf("Wrong key length for generated 2DES key: %d", len(key));
      }

      if _, ok := checkParityBytes(key); ok != true {
        t.Errorf("2DES Key with incorrect parity generated!")
      }
    } // else

    // 3DES
    if key, err := GenerateDES3Key(); err != nil {
      t.Errorf("Error generating key!")
    } else {
      if 24 != len(key) {
        t.Errorf("Wrong key length for generated 3DES key: %d", len(key));
      }

      if _, ok := checkParityBytes(key); ok != true {
        t.Errorf("3DES Key with incorrect parity generated!")
      }
    } // else

  } // for
}





