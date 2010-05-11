package des


const (
  odd =1
  even=0
)

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
