package main

import (
  "crypto/des"

  "crypto/aes"

  "crypto/block"
  "io"
  "os"
  "fmt"
  "time"
  "math"
  "container/vector"
)


var (
  key   = []byte {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
  key2  = []byte {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                  0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
  key3  = []byte {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                  0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                  0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67}

  aes128key = []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
  aes192key = []byte{0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
			               0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,}
  aes256key = []byte{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
			               0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,}

  cipher_names = []string {"DES", "2DES", "3DES", "AES128", "AES192", "AES256"}
)


func create_ciphers() (*[]block.Cipher) {
  ciphers := make([]block.Cipher,6)
  ciphers[0], _ = des.NewDESCipher(key)
  ciphers[1], _ = des.NewDES2Cipher(key2)
  ciphers[2], _ = des.NewDES3Cipher(key3)
  ciphers[3], _ = aes.NewCipher(aes128key)
  ciphers[4], _ = aes.NewCipher(aes192key)
  ciphers[5], _ = aes.NewCipher(aes256key)
  return &ciphers
}

func gen_iv(c block.Cipher) []byte {
  return make([]byte, c.BlockSize())
}

func create_readers(ciphers *[]block.Cipher) (*[]io.Reader){
  reader := &NullReaderWriter{}
  

  // ECB, CBC, CTR, OFB ...?
  readers := make([]io.Reader, len(*ciphers)*4)

  for i, cipher := range(*ciphers) {

    readers[i]                   = block.NewECBDecrypter(cipher, io.LimitReader(reader, 1024 * 1024 * 16))
    readers[i +   len(*ciphers)] = block.NewCBCDecrypter(cipher, gen_iv(cipher), io.LimitReader(reader, 1024 * 1024 * 16))
    readers[i + 2*len(*ciphers)] = block.NewCTRReader   (cipher, gen_iv(cipher), io.LimitReader(reader, 1024 * 1024 * 16))
    readers[i + 3*len(*ciphers)] = block.NewOFBReader   (cipher, gen_iv(cipher), io.LimitReader(reader, 1024 * 1024 * 16))

  }
  return &readers
}

func bench_dec (reader io.Reader)(int64) {
  var err os.Error

  n, _n := 0,0
  arr   := make([]byte, 1024)
  time_ := time.Nanoseconds()

  for {
    if _n, err = reader.Read(arr); err != nil {
      break;
    }
    n += _n
  }
  print(".")
  return (time.Nanoseconds()-time_)/1000
}



// create a benchmark for DES and TDES comparing it to other
// impls in the go system.
// Start of:
// This is meant as informative if other people end up needing 
// some crypto performance. Note that the numbers will vary 
// wildly depending on the machine (the test was run on amd64, 
// warm cache, 5 runs of 16mb the last 4 of which were measured, 
// no spikes observed and averaged into the numbers). 
//  Taru Karttunen 2010-05-11 go mailing list.

func runBenchmark() {
  // chaining modes
  //  DES 2DES 3DES AES
  //      run once
  //      for i in Xtimes 
  //        startTime
  //          doEncryption
  //        endTime
  //
  //    min, max, avg, dev

  ciphers := create_ciphers()
  var results []vector.Vector
      results = make([]vector.Vector,24)
  for t_ := 0; t_!=10; t_++ {
    for i, reader := range(*create_readers(ciphers)) {
      results[i].Push(bench_dec(reader))
    }
  }
  print_results(results)
  /*
  println()

  var fresult float
  for i, result := range(results) {
    // nanoseconds / 16MB

    r,_ := result.(int64)

    fresult = float(r) / 1000000000
    // sec per 16
    fresult /= 16
    fresult = 1/(fresult)
    fmt.Printf("%2d : %02f\n", i, fresult);
  }
  */
}

func n_min_max_avg_dev (arr_int64 vector.Vector) (n int, min int64, max int64, avg int64, dev float64) {
  var sum int64
  
  n   = len(arr_int64)
  min = 0x7fffffffffffffff 
  for _, r_ := range(arr_int64) {
    r, _ := r_.(int64)

    sum += r

    if r < min {
      min = r
    }
    if r > max {
      max = r
    }
  }
  avg = sum / int64(n)

  var vari int64
  for _, r_ := range(arr_int64) {
    r, _ := r_.(int64)
  
    d := r-avg
    vari += (d * d)
  }
  vari = vari/int64(n)
  dev  = math.Sqrt(float64(vari))
  return
}


func print_results(results []vector.Vector) {
  println()

  for _, result := range(results) {
    n, min, max, avg, dev := n_min_max_avg_dev(result) 
    for _, r_ := range(result) {
      r,_ := r_.(int64)
      fmt.Printf("%d ",r)
    }
    println()
    fmt.Printf("(%d) %d < %d < %d  %02f\n", n, min, avg, max, dev);
  }
}

func main() {
  //runBenchmark()
  var v vector.Vector
  v.Push(int64(2))
  v.Push(int64(4))
  v.Push(int64(4))
  v.Push(int64(4))
  v.Push(int64(5))
  v.Push(int64(5))
  v.Push(int64(7))
  v.Push(int64(9))
  n, min, max, avg, dev := n_min_max_avg_dev(v) 
  fmt.Printf("(%d) %d < %d < %d  %02f\n", n, min, avg, max, dev);
}



// Below is a noop reader/writer implementation
//type Reader interface {
//    Read(p []byte) (n int, err os.Error)
//}
type NullReaderWriter struct {
}

func (r *NullReaderWriter) Read(p []byte)(n int, err os.Error){
  for i := range(p) {
    p[i] = 0x77
  }
  return len(p), nil
}
//type Writer interface {
//    Write(p []byte) (n int, err os.Error)
//}
func (r NullReaderWriter) Write (p []byte) (n int, err os.Error) {
  return len(p), nil;
}


