// Package crypto implements all cryptographic primitives required for
// the SpideyAuth v3.4 protocol. Every algorithm is a 1:1 port of the
// original Lua 5.1 client code found in spideyauth_client.lua.
//
// CRITICAL CORRECTIONS vs the published spec document:
//
//  1. PRNG return formula: The spec says `min + newState%(max-min+1)`.
//     The actual Lua client (line 736) computes:
//       rangeMin + newState % rangeMax - rangeMin + 1
//     which simplifies to: newState % rangeMax + 1
//     The min parameter is entirely vestigial. This implementation
//     uses the correct formula.
//
//  2. Cipher key indexing is 0-based (Lua table uses [0]=...).
//     The initial request key is a single-element slice {0}.
//
//  3. Extended 8-byte key layout (interleaved):
//     [ct1%256, extKey1, ct2%256, extKey3, ct3%256, extKey5, ct4%256, extKey7]
//
//  4. Heartbeat payload has NO checksum prepend (unlike init/start).
//
//  5. Start serverProof uses stringChecksum("?") = 63 (fallback JobId).
package crypto

import (
	"math"
	"strconv"
	"strings"
)

// ────────────────────────────────────────────────────────────────────────────
// Custom Base-16 encoding (SpideyAuth nibble encoding)
// Symbol set (index 0..15): a b Q k O I 1 l 0 9 E 3 J 7 G T
// ────────────────────────────────────────────────────────────────────────────

var encodeSymbols = []byte("abQkOI1l09E3J7GT")
var decodeSymbols [256]byte

func init() {
	for i, b := range encodeSymbols {
		decodeSymbols[b] = byte(i)
	}
}

// EncodeNibbles converts a single byte into its two-symbol representation.
func EncodeNibbles(b byte) string {
	return string([]byte{encodeSymbols[b>>4], encodeSymbols[b&0x0F]})
}

// DecodeNibbles converts a two-symbol string back to a byte.
// Panics if s is shorter than 2 bytes.
func DecodeNibbles(s string) byte {
	return (decodeSymbols[s[0]] << 4) | decodeSymbols[s[1]]
}

// ────────────────────────────────────────────────────────────────────────────
// PRNG  (matches Lua createPRNG in Section 8 of the client, NOT the HWID PRNG)
// ────────────────────────────────────────────────────────────────────────────

// PRNG is a linear congruential generator that exactly matches the Lua client.
type PRNG struct {
	multiplier int64
	increment  int64
	modulus    int64
	state      int64
	counter    int64
}

// NewPRNG creates a new PRNG seeded with the given value.
func NewPRNG(seed int64) *PRNG {
	return &PRNG{
		multiplier: 1103515245,
		increment:  12345,
		modulus:    99999999,
		state:      seed % 2147483648,
		counter:    1,
	}
}

// Next returns the next pseudo-random value.
//
// IMPORTANT: This matches the actual Lua formula exactly:
//
//	return rangeMin + newState % rangeMax - rangeMin + 1
//	     = newState % rangeMax + 1
//
// The rangeMin parameter cancels out; only rangeMax determines the range.
func (p *PRNG) Next(rangeMin, rangeMax int64) int64 {
	raw := p.multiplier*p.state + p.increment
	newState := raw%p.modulus + p.counter
	p.counter++
	p.state = newState
	p.increment = (raw % 4859) * (p.modulus % 5781)
	return newState%rangeMax + 1
}

// ────────────────────────────────────────────────────────────────────────────
// Numeric Hash
// ────────────────────────────────────────────────────────────────────────────

// NumericHash is a 1:1 port of the Lua numericHash function.
// Produces the same output as the Lua client for any int64 input.
func NumericHash(input int64) int64 {
	for i := 0; i < 2; i++ {
		a := input%9915 + 4
		var b, c int64

		for iter := 1; iter <= 3; iter++ {
			b = input%4155 + 3
			if iter%2 == 1 {
				b += 522
			}
			c = input%9996 + 1
			if c%2 != 1 {
				c *= 3
			}
		}

		d := input%9999995 + 1 + 13729
		low3 := input % 1000
		mid3 := (input-low3) / 1000 % 1000
		combined := low3*mid3 + d + input%(419824125-d+low3)
		e := input%(a*b+9999) + 13729
		input = (combined + (e+(low3*b+mid3))%999999*(d+e%c)) % 99999999999
	}
	return input
}

// StringChecksum sums all byte values in a string (matches Lua stringChecksum).
func StringChecksum(s string) int64 {
	var sum int64
	for i := 0; i < len(s); i++ {
		sum += int64(s[i])
	}
	return sum
}

// ────────────────────────────────────────────────────────────────────────────
// Stream Cipher  (used by the string obfuscation system, not the protocol)
// ────────────────────────────────────────────────────────────────────────────

// StreamCipher matches the Lua stream byte generator (Section 3).
type StreamCipher struct {
	seed   uint64
	prng   uint64
	buffer []byte
}

// NewStreamCipher creates a stream cipher with the given seed and prng state.
func NewStreamCipher(seed, prng uint64) *StreamCipher {
	return &StreamCipher{seed: seed, prng: prng}
}

// NextByte returns the next byte from the stream.
func (s *StreamCipher) NextByte() byte {
	if len(s.buffer) == 0 {
		s.seed = (s.seed*169 + 7579774851987) % 35184372088832
		for {
			s.prng = (s.prng * 27) % 257
			if s.prng != 1 {
				break
			}
		}
		shift := s.prng % 32
		// Replicate Lua:  floor(seed / 2^(13 - (prng-shift)/32)) % 4294967296 / 2^shift
		exp := uint(13 - (s.prng-shift)/32)
		seedDiv := (s.seed >> exp) % 4294967296
		raw := float64(seedDiv) / math.Pow(2, float64(shift))
		combined := uint64(math.Floor(math.Mod(raw, 1)*4294967296)) + uint64(math.Floor(raw))

		low16 := combined % 65536
		high16 := (combined - low16) / 65536
		b0 := byte(low16 % 256)
		b1 := byte((low16 - uint64(b0)) / 256)
		b2 := byte(high16 % 256)
		b3 := byte((high16 - uint64(b2)) / 256)
		s.buffer = []byte{b0, b1, b2, b3}
	}
	b := s.buffer[0]
	s.buffer = s.buffer[1:]
	return b
}

// ────────────────────────────────────────────────────────────────────────────
// Protocol Cipher  (encode/decode for auth messages)
// ────────────────────────────────────────────────────────────────────────────

// Cipher handles the subtraction-based stream cipher used for auth messages.
//
// Encoding (server → client):  cipherByte = (plainByte - key[i] + 4096) % 256
// Decoding (client → server):  plainByte  = (cipherByte + key[i]) % 256
//
// Key indices are 0-based (matching Lua table { [0]=..., [1]=..., ... }).
type Cipher struct {
	key    []int64
	encPos int
	decPos int
}

// NewCipher creates a Cipher with the provided key.
// key must be a 0-indexed slice of byte values (0–255).
func NewCipher(key []int64) *Cipher {
	return &Cipher{key: key}
}

// ResetEnc resets the encode position to 0 (matches configureCipher(2)).
func (c *Cipher) ResetEnc() {
	c.encPos = 0
}

// ResetDec resets the decode position to 0 (matches start of decodeMessage).
func (c *Cipher) ResetDec() {
	c.decPos = 0
}

// encodeByte encodes one byte and advances the encode key position.
func (c *Cipher) encodeByte(b byte) string {
	val := (int64(b) + 4096 - c.key[c.encPos]) % 256
	c.encPos = (c.encPos + 1) % len(c.key)
	return EncodeNibbles(byte(val))
}

// EncodeString encodes a length-prefixed string.
// First emits the length byte (ciphered), then each content byte (ciphered).
func (c *Cipher) EncodeString(s string) string {
	var sb strings.Builder
	sb.WriteString(c.encodeByte(byte(len(s))))
	for i := 0; i < len(s); i++ {
		sb.WriteString(c.encodeByte(s[i]))
	}
	return sb.String()
}

// EncodeStrings encodes multiple strings back-to-back with the same cipher.
func (c *Cipher) EncodeStrings(fields []string) string {
	var sb strings.Builder
	for _, f := range fields {
		sb.WriteString(c.EncodeString(f))
	}
	return sb.String()
}

// EncodeStringRaw encodes a length-prefixed string WITHOUT cipher (skipAccum=true).
// Used only for the checksum prepend on client→server payloads.
// The server does NOT need to prepend this to its responses.
func EncodeStringRaw(s string) string {
	var sb strings.Builder
	sb.WriteString(EncodeNibbles(byte(len(s))))
	for i := 0; i < len(s); i++ {
		sb.WriteString(EncodeNibbles(s[i]))
	}
	return sb.String()
}

// DecodeMessage decodes an encoded message into a slice of strings.
// Decoding uses addition: plainByte = (cipherByte + key[decPos]) % 256.
// The decode position is reset to 0 at the start of every call.
//
// Each decoded string is assembled from raw bytes (matching Lua's byteMap[val]
// which is string.char(val)), so the returned strings may contain arbitrary bytes.
func (c *Cipher) DecodeMessage(encoded string) []string {
	c.decPos = 0
	var result []string
	pos := 0

	for pos+2 <= len(encoded) {
		// Decode length byte
		rawLen := int(DecodeNibbles(encoded[pos : pos+2]))
		rawLen = int((int64(rawLen) + c.key[c.decPos]) % 256)
		c.decPos = (c.decPos + 1) % len(c.key)
		pos += 2

		// Decode content
		var sb strings.Builder
		for i := 0; i < rawLen; i++ {
			if pos+2 > len(encoded) {
				break
			}
			b := int(DecodeNibbles(encoded[pos : pos+2]))
			b = int((int64(b) + c.key[c.decPos]) % 256)
			c.decPos = (c.decPos + 1) % len(c.key)
			sb.WriteByte(byte(b))
			pos += 2
		}
		result = append(result, sb.String())
	}
	return result
}

// ────────────────────────────────────────────────────────────────────────────
// Key construction helpers
// ────────────────────────────────────────────────────────────────────────────

// InitialKey is the single-byte key used to decode the client's init request.
var InitialKey = []int64{0}

// FourByteKey builds the 4-byte cipher key from client tokens (mod 256).
// This is used to encode the init response.
func FourByteKey(ct1, ct2, ct3, ct4 int64) []int64 {
	return []int64{ct1 % 256, ct2 % 256, ct3 % 256, ct4 % 256}
}

// EightByteKey builds the 8-byte extended cipher key used for start/heartbeat.
// Layout (0-indexed): [ct1%256, ek1, ct2%256, ek3, ct3%256, ek5, ct4%256, ek7]
// ek1/3/5/7 are server-generated random byte values returned in the init response.
func EightByteKey(ct1, ct2, ct3, ct4, ek1, ek3, ek5, ek7 int64) []int64 {
	return []int64{
		ct1 % 256, ek1,
		ct2 % 256, ek3,
		ct3 % 256, ek5,
		ct4 % 256, ek7,
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Protocol-level helpers
// ────────────────────────────────────────────────────────────────────────────

// BuildInitServerProof builds the server proof string included in the init response.
// If lifetime is true, the proof encodes a lifetime license.
//
// The client verifies (Lua, 1-indexed initResponse[11]):
//
//	Lifetime:     numericHash(sn3+8474) .. numericHash(sn1+31)  .. numericHash(sn2+4491)
//	Non-lifetime: numericHash(sn3+8474) .. numericHash(sn1+69)  .. numericHash(sn2+4491)
//
// sn1/2/3 are the client's serverNonces from the init request payload.
func BuildInitServerProof(sn1, sn2, sn3 int64, lifetime bool) string {
	mid := int64(69)
	if lifetime {
		mid = 31
	}
	return strconv.FormatInt(NumericHash(sn3+8474), 10) +
		strconv.FormatInt(NumericHash(sn1+mid), 10) +
		strconv.FormatInt(NumericHash(sn2+4491), 10)
}

// BuildStartServerProof builds the server proof string included in the start response.
//
// The client verifies (Lua startResponse[3], tries jobId then "?" fallback):
//
//	numericHash(sn5+181) .. numericHash(sn4+stringChecksum(jobId)) .. numericHash(sn6+sn2_init)
//
// Since the server cannot know the Roblox JobId, we use stringChecksum("?") = 63,
// which matches the client's second attempt (jobIdFallback = true).
//
// sn4/5/6 come from the start request payload; sn2Init is the client's
// serverNonce[2] from the original init request.
func BuildStartServerProof(sn4, sn5, sn6, sn2Init int64) string {
	const jobIdFallbackChecksum = 63 // stringChecksum("?")
	return strconv.FormatInt(NumericHash(sn5+181), 10) +
		strconv.FormatInt(NumericHash(sn4+jobIdFallbackChecksum), 10) +
		strconv.FormatInt(NumericHash(sn6+sn2Init), 10)
}

// BuildHeartbeatGoodResponse computes the expected "good" heartbeat response value.
func BuildHeartbeatGoodResponse(hbNonce1, hbNonce2, combinedSeed int64) string {
	return strconv.FormatInt(NumericHash(hbNonce1*hbNonce2%100000+combinedSeed+8410), 10)
}

// BuildHeartbeatShutdownResponse computes the "shutdown" heartbeat response value.
func BuildHeartbeatShutdownResponse(hbNonce1, hbNonce2, combinedSeed int64) string {
	return strconv.FormatInt(NumericHash(hbNonce1*hbNonce2%100000+combinedSeed+8410+4919), 10)
}