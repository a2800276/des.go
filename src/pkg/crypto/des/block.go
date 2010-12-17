package des

import (
  "fmt"
)

func desfunc (dst, src []byte, key [] uint32 ) {
  var left, right, work uint32;
  // DEBUG
  //dumpRKeys("final keys", key);
  // DEBUG
  left  = uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	right = uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])

  work   = ((left >> 4) ^ right) & 0x0f0f0f0f;
	right ^= work;
	left  ^= (work << 4);
	work   = ((left >> 16) ^ right) & 0x0000ffff;
	right ^= work;
	left  ^= (work << 16);
	work   = ((right >> 2) ^ left) & 0x33333333;
	left  ^= work;
	right ^= (work << 2);
	work   = ((right >> 8) ^ left) & 0x00ff00ff;
	left  ^= work;
	right ^= (work << 8);
	right  = ((right << 1) | ((right >> 31) & 1)) & 0xffffffff;
	work   = (left ^ right) & 0xaaaaaaaa;
	left  ^= work;
	right ^= work;
	left = ((left << 1) | ((left >> 31) & 1)) & 0xffffffff;


  for round , k := 0,0 ; round < 8 ; round, k = round+1, k+4 {
    work  = (right << 28) | (right >> 4);
    work ^= key[k];
    //k+=1

    fval := SP7[ work        & 0x3f];
		fval |= SP5[(work >>  8) & 0x3f];
		fval |= SP3[(work >> 16) & 0x3f];
		fval |= SP1[(work >> 24) & 0x3f];
    work  = right ^ key[k+1];

		fval |= SP8[ work		     & 0x3f];
		fval |= SP6[(work >>  8) & 0x3f];
		fval |= SP4[(work >> 16) & 0x3f];
		fval |= SP2[(work >> 24) & 0x3f];

    left ^= fval;

    work  = (left << 28) | (left >> 4);
		work ^= key[k+2];

    fval  = SP7[ work		     & 0x3f];
		fval |= SP5[(work >>  8) & 0x3f];
		fval |= SP3[(work >> 16) & 0x3f];
		fval |= SP1[(work >> 24) & 0x3f];

		work  = left ^ key[k+3];

		fval |= SP8[ work		     & 0x3f];
		fval |= SP6[(work >>  8) & 0x3f];
		fval |= SP4[(work >> 16) & 0x3f];
		fval |= SP2[(work >> 24) & 0x3f];
		right ^= fval;
  }

  right  = (right << 31) | (right >> 1);
	work   = (left ^ right) & 0xaaaaaaaa;
	left  ^= work;
	right ^= work;
	left   = (left << 31) | (left >> 1);
	work   = ((left >> 8) ^ right) & 0x00ff00ff;
	right ^= work;
	left  ^= (work << 8);
	work   = ((left >> 2) ^ right) & 0x33333333;
	right ^= work;
	left  ^= (work << 2);
	work   = ((right >> 16) ^ left) & 0x0000ffff;
	left  ^= work;
	right ^= (work << 16);
	work   = ((right >> 4) ^ left) & 0x0f0f0f0f;
	left  ^= work;
	right ^= (work << 4);

  dst[0] = (byte)(right >> 24)
  dst[1] = (byte)(right >> 16)
  dst[2] = (byte)(right >>  8)
  dst[3] = (byte)(right)
  dst[4] = (byte)(left >> 24)
  dst[5] = (byte)(left >> 16)
  dst[6] = (byte)(left >>  8)
  dst[7] = (byte)(left)

  return;
}

func deskey (key []byte, cipher *DES) {

  // DEBUG
  // dump("initial", key)
  // DEBUG

  var pc1m, pcr uint64


  var bit uint
	for bit = 0; bit < 56; bit++  {
    // pick the 56 'proper' bits out of the key
		bit_perm := pc1[bit];  // bit_perm should be at position `bit` in the permuted key
		m := bit_perm & 07;
    if 0 != (key[bit_perm >> 3] & (0x80 >> m)) {
       pc1m |= (1 << bit)
    }
  }
  // DEBUG
  // for bit = 0; bit!=64; bit++ {
  //  val := pc1m & (1 << bit)
  //  fmt.Printf("%2d => %d\n", bit, val)
  // }
  // DEBUG 

  // Generate 16 round keys
  // round keys are 64 bit and stored in two 32 bit values.
  // This is due to historical reasons. The code this port is 
  // based upon is oldish C code from a time where 32 bit was
  // 'long long long long long int' :)
  // This should be changed in near futture avoid dragging around
  // an implementation artefact.
	for round := 0; round < 16; round++  {

    m:= round << 1
    n:= m+1

    cipher.enc[m], cipher.enc[n] = 0,0 // Shouldn't need to zero out keys, ... would anyone reuse cipher?
                                       // AES impl has a `reset` function for the cipher ...

    // Two 28 bit key halfs are rotated according to totrot...
    first_half := 0xfffffff &  pc1m
    secnd_half := 0xfffffff & (pc1m >> 28)

    rotate_by  := totrot[round]
    // DANGER : is this correct?
    first_rot  := ((first_half >> rotate_by) | first_half << (28 - rotate_by)) & 0xfffffff
    secnd_rot  := ((secnd_half >> rotate_by) | secnd_half << (28 - rotate_by)) & 0xfffffff
    // DANGER 

    // DEBUG 
    //fmt.Printf("Round %d => %08X || %08X\n", round, first_rot, secnd_rot) 
    // DEBUG 

    pcr = first_rot | (secnd_rot << 28)

    // DEBUG 
    // fmt.Printf("%02d %056b\n", round, pcr)
    // DEBUG 

    // Compression Permutation
    // pick 48 out of 56 bits...

		for bit = 0; bit < 24; bit++  {
      if 0 != pcr & ( 1 << pc2[bit   ]) {
        cipher.enc[m] |= 1 << (23-bit)
      }
      if 0 != pcr & ( 1 << pc2[bit+24]) {
        cipher.enc[n] |= 1 << (23-bit)
      }
	  }
  }

  // dec keys are enc keys swapped backwards...
  for i := 0; i != 32; i+=2 {
    cipher.dec[30-i] = cipher.enc[i]
    cipher.dec[31-i] = cipher.enc[i+1]
  }
  // DEBUG 
  // dumpRKeys("before cooking", cipher.enc)
  // DEBUG 

	cipher.enc = cookey(cipher.enc);
  cipher.dec = cookey(cipher.dec);

}

/* TODO pass references here? */

func cookey (rawkey []uint32) []uint32 {
// Performs some precalculations/optimizations on the key material
// You can read about the motivation in a sci.cypt post by Richard 
// Outerbridge who's public domain DES implementation is the basis of
// this and --via Applied Cryptography-- many many further implementations.
// http://groups.google.com/group/sci.crypt/browse_thread/thread/
//      2829f9b4b108abc0/9015d8095dd776b7?lnk=gst&q=cookey#9015d8095dd776b7

  var cooked_keys = make([]uint32, 32)

  for i := 0; i != 32; i+=2 {

    cooked_keys[i  ]  = ((rawkey[i  ] & 0x00FC0000) <<  6)
    cooked_keys[i  ] |= ((rawkey[i  ] & 0x00000FC0) << 10)
    cooked_keys[i  ] |= ((rawkey[i+1] & 0x00FC0000) >> 10)
    cooked_keys[i  ] |= ((rawkey[i+1] & 0x00000FC0) >>  6)

    cooked_keys[i+1]  = ((rawkey[i  ] & 0x0003F000) << 12)
    cooked_keys[i+1] |= ((rawkey[i  ] & 0x0000003F) << 16)
    cooked_keys[i+1] |= ((rawkey[i+1] & 0x0003F000) >>  4)
    cooked_keys[i+1] |=  (rawkey[i+1] & 0x0000003F)
  }

  return cooked_keys
}

// DEBUG
func dumpRKeys (mes string, key [] uint32) {
  println(mes)
  for i, k := range(key) {
    fmt.Printf("%2d => %08X\n", i, k)
  }

}
func dump (mes string, bytes []byte) {
  println(mes)
  for _,b := range(bytes) {
    fmt.Printf("0x%0X ", b)
  }
  println("")
}
// DEBUG


