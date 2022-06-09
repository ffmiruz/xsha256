package xsha256

// Add modulo 2^32
func AddMod32(a, b uint32) uint32 {
	return (a + b) & 0xFFFFFFFF
}

// Right rotate
func RotR32(a uint32, shift uint32) uint32 {
	return (a >> shift) | (a << (32 - shift))
}

func Little_Sigma0(x uint32) uint32 {
	return RotR32(x, 7) ^ RotR32(x, 18) ^ (x >> 3)
}

func Little_Sigma1(x uint32) uint32 {
	return RotR32(x, 17) ^ RotR32(x, 19) ^ (x >> 10)
}

// SHA-256 message block is 64 bytes. So one message block contains 16 words.
// SHA_256 has 64 rounds. First 16 rounds use 16 message words directly.
// Subsequent rounds mix differnt words using a formula.

// Convert 64 bytes into 16 words. Convert in 4 bytes group into integer using big endian.
// For next 48 words using formula:
// 	words[i] := words[i-16] + little_sigma0(words[i-15]) + words[i-7] + little_sigma1(words[i-2])
func BytesToWords(b []byte) []uint32 {
	words := make([]uint32, 64)
	for i := 0; i < 16; i++ {
		// slice of bytes into uint32
		words[i] = uint32(b[i*4+0])<<24 | uint32(b[i*4+1])<<16 | uint32(b[i*4+2])<<8 | uint32(b[i*4+3])
	}
	for i := 16; i < 64; i++ {
		words[i] = words[i-16] + Little_Sigma0(words[i-15]) + words[i-7] + Little_Sigma1(words[i-2])
	}
	return words
}

func Big_Sigma0(x uint32) uint32 {
	return RotR32(x, 2) ^ RotR32(x, 13) ^ RotR32(x, 22)
}

func Big_Sigma1(x uint32) uint32 {
	return RotR32(x, 6) ^ RotR32(x, 11) ^ RotR32(x, 25)
}

// Each bit is according to the bit from y or z at this index,
// depending on if the bit from x at this index is 1 or 0).
func Choice(x, y, z uint32) uint32 {
	return (x & y) ^ ((^x) & z)
}

// For each bit index, that result bit is according to the majority
// of the 3 inputs bits for x y and z at this index.
func Majority(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

type State struct {
	list [8]uint32
}

// https://en.wikipedia.org/wiki/SHA-2#Pseudocode
func Round(state *State, roundK uint32, word uint32) {
	ch := Choice(state.list[4], state.list[5], state.list[6])
	temp1 := state.list[7] + Big_Sigma1(state.list[4]) + ch + roundK + word
	maj := Majority(state.list[0], state.list[1], state.list[2])
	temp2 := Big_Sigma0(state.list[0]) + maj

	state.list[7] = state.list[6]
	state.list[6] = state.list[5]
	state.list[5] = state.list[4]
	state.list[4] = state.list[3] + temp1
	state.list[3] = state.list[2]
	state.list[2] = state.list[1]
	state.list[1] = state.list[0]
	state.list[0] = temp1 + temp2
}

// NOTE: cube roots of the first 64 prime numbers.
var ROUND_CONSTANT = []uint32{
	0x428a2f98,
	0x71374491,
	0xb5c0fbcf,
	0xe9b5dba5,
	0x3956c25b,
	0x59f111f1,
	0x923f82a4,
	0xab1c5ed5,
	0xd807aa98,
	0x12835b01,
	0x243185be,
	0x550c7dc3,
	0x72be5d74,
	0x80deb1fe,
	0x9bdc06a7,
	0xc19bf174,
	0xe49b69c1,
	0xefbe4786,
	0x0fc19dc6,
	0x240ca1cc,
	0x2de92c6f,
	0x4a7484aa,
	0x5cb0a9dc,
	0x76f988da,
	0x983e5152,
	0xa831c66d,
	0xb00327c8,
	0xbf597fc7,
	0xc6e00bf3,
	0xd5a79147,
	0x06ca6351,
	0x14292967,
	0x27b70a85,
	0x2e1b2138,
	0x4d2c6dfc,
	0x53380d13,
	0x650a7354,
	0x766a0abb,
	0x81c2c92e,
	0x92722c85,
	0xa2bfe8a1,
	0xa81a664b,
	0xc24b8b70,
	0xc76c51a3,
	0xd192e819,
	0xd6990624,
	0xf40e3585,
	0x106aa070,
	0x19a4c116,
	0x1e376c08,
	0x2748774c,
	0x34b0bcb5,
	0x391c0cb3,
	0x4ed8aa4a,
	0x5b9cca4f,
	0x682e6ff3,
	0x748f82ee,
	0x78a5636f,
	0x84c87814,
	0x8cc70208,
	0x90befffa,
	0xa4506ceb,
	0xbef9a3f7,
	0xc67178f2,
}

// The mixing loop.
func Compress(state *State, block []byte) {
	words := BytesToWords(block)
	before := State{list: state.list}

	for i := 0; i < 64; i++ {
		Round(state, ROUND_CONSTANT[i], words[i])
	}

	// Add the compressed chunk to the current hash value.
	state.list[0] = state.list[0] + before.list[0]
	state.list[1] = state.list[1] + before.list[1]
	state.list[2] = state.list[2] + before.list[2]
	state.list[3] = state.list[3] + before.list[3]
	state.list[4] = state.list[4] + before.list[4]
	state.list[5] = state.list[5] + before.list[5]
	state.list[6] = state.list[6] + before.list[6]
	state.list[7] = state.list[7] + before.list[7]
}

// Padding scheme:
// 	Start the padding bitstring with a single 1-bit.
// 	Append some 0-bits after that. We'll define how many in step 4 below.
// 	Append the bit-length of the message, encoded as a 64-bit unsigned big-endian number.
// 	Choose the number of 0-bits for step 2 to be the smallest number such that
//		the total bit-length of the message plus the padding is an exact multiple of 512.
//
// Padding scheme, redescribed in terms of bytes:
// Start the padding bytestring with a single 0x80 byte (0b10000000)
// Append some 0x00 bytes after that. We'll define how many in step 4 below.
// Append 8 times the byte-length of the message, encoded as an 8-byte unsigned big-endian number.
// Choose the number of 0x00 bytes for step 2 to be the smallest number
// 	such that the total byte-length of the message plus the padding is an exact multiple of 64.

func Padding(len uint64) []byte {
	remainder := (len + 8) % 64
	filler := 64 - remainder
	zero := filler - 1
	padSize := 1 + zero + 8
	pad := make([]byte, padSize)
	pad[0] = 0x80

	len *= 8
	pad[padSize-1] = byte(len >> 0)
	pad[padSize-2] = byte(len >> 8)
	pad[padSize-3] = byte(len >> 16)
	pad[padSize-4] = byte(len >> 24)
	pad[padSize-5] = byte(len >> 32)
	pad[padSize-6] = byte(len >> 40)
	pad[padSize-7] = byte(len >> 48)
	pad[padSize-8] = byte(len >> 56)

	return pad
}

// Initialization vector
var IV = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// msg is padded. padded msg is chunked into 64 bytes block.
// block is mixed(Compress) with current state.
// The resulting state is used as state for next block mixing.
func Hash(msg []byte) []byte {
	pad := Padding(uint64(len(msg)))
	paddedMsg := append(msg, pad...)
	state := &State{list: IV}

	for i := 0; i < len(paddedMsg); i += 64 {
		block := paddedMsg[i : i+64]
		Compress(state, block)
	}
	hash := make([]byte, 0, 32)
	v := [4]byte{}
	for i := 0; i < 8; i++ {
		// uint32 to array of bytes
		v[0] = byte(state.list[i] >> 24)
		v[1] = byte(state.list[i] >> 16)
		v[2] = byte(state.list[i] >> 8)
		v[3] = byte(state.list[i])

		hash = append(hash, v[:]...)
	}
	return hash
}
