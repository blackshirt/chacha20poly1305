// Copyright (c) 2022 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// AEAD_CHACHA20_POLY1305 is an authenticated encryption with additional
//  data algorithm.  The inputs to AEAD_CHACHA20_POLY1305 are:
//   A 256-bit key
//   A 96-bit nonce -- different for each invocation with the same key
//   An arbitrary length plaintext
//   Arbitrary length additional authenticated data (AAD)
module chacha20poly1305

import encoding.binary
import crypto.internal.subtle
import x.crypto.chacha20
import x.crypto.poly1305

// This interface was a proposed draft of `AEAD` interfaces likes discussion at discord channel.
// see https://discord.com/channels/592103645835821068/592320321995014154/1206029352412778577
// Authenticated Encryption with Additional Data (AEAD) interface
interface AEAD {
	// nonce_size return the nonce size (in bytes) used by this AEAD algorithm that should be
	// passed to `.encrypt` or `.decrypt`.
	nonce_size() int
	// tag_size returns the authenticated tag size (in bytes) produced by this AEAD algorithm.
	tag_size() int
	// overhead returns the maximum difference between the lengths of a plaintext and its ciphertext.
	overhead() int
	// encrypt encrypts and authenticates the provided plaintext along with a nonce, and associated data.
	// It returns the ciphertext and appends the result into the dst.
	// The nonce must be `nonce_size()` bytes long and required to be unique for all time, for a given key
	encrypt(plaintext []u8, nonce []u8, aad []u8) ![]u8
	// decrypt decrypts and authenticates (verifies) the provided ciphertext along with a nonce, and
	// associated data. If successful,  it returns the plaintext and appends the resulting plaintext to dst.
	decrypt(ciphertext []u8, nonce []u8, aad []u8) ![]u8
}

const key_size = 32
const nonce_size = 12
const x_nonce_size = 24
const tag_size = 16

struct Chacha20Poly1305 {
	key    []u8 = []u8{len: chacha20poly1305.key_size}
	ncsize int  = chacha20poly1305.nonce_size
}

fn new(key []u8, ncsize int) !&AEAD {
	if key.len != chacha20poly1305.key_size {
		return error('chacha20poly1305: bad key size')
	}
	if ncsize != chacha20poly1305.nonce_size && ncsize != chacha20poly1305.x_nonce_size {
		return error('chacha20poly1305: bad nonce size supplied, its should 12 or 24')
	}
	c := &Chacha20Poly1305{
		key: key
		ncsize: ncsize
	}
	return c
}

fn (c Chacha20Poly1305) nonce_size() int {
	return c.ncsize
}

fn (c Chacha20Poly1305) tag_size() int {
	return chacha20poly1305.tag_size
}

fn (c Chacha20Poly1305) overhead() int {
	return chacha20poly1305.tag_size
}

fn (c Chacha20Poly1305) encrypt(plaintext []u8, nonce []u8, aad []u8) ![]u8 {
	if nonce.len != c.nonce_size() {
		return error('chacha20poly1305: unmatching nonce size')
	}
	// check if the plaintext length doesn't exceed the amount of limit.
	// its comes from the internal of chacha20 mechanism, where the counter are u32
	// with the facts of 64 bytes block of chacha20 operates on, we can measure the amount
	// of encrypted data possible in a single invocation, ie.,
	// amount = (2^32-1)*64 = 274,877,906,880 bytes, or nearly 256 GB
	if u64(plaintext.len) > (u64(1) << 38) - 64 {
		panic('chacha20poly1305: plaintext too large')
	}
	return c.encrypt_generic(plaintext, nonce, aad)
}

fn (c Chacha20Poly1305) encrypt_generic(plaintext []u8, nonce []u8, aad []u8) ![]u8 {
	// First, generates a Poly1305 one-time key from the 256-bit key
    // and nonce. Actually its generates by performing ChaCha20 key stream function,
	// and take
	// see https://datatracker.ietf.org/doc/html/rfc8439#section-2.6
	mut polykey := []u8{len: chacha20poly1305.key_size}
	mut ciphertext := []u8{len: plaintext.len}
	mut s := chacha20.new_cipher(c.key, nonce)!
	s.xor_key_stream(mut polykey, polykey)

	// Next, the ChaCha20 encryption function is called to encrypt the
	// plaintext, using the same key and nonce, and with the initial
	// counter set to 1.
	s.set_counter(1)
	s.xor_key_stream(mut ciphertext, plaintext)

	// Finally, the Poly1305 function is called with the Poly1305 key
	// calculated above, and a message constructed as a concatenation of
	// the following:
	mut b8 := []u8{len: 8}
	mut pad_msg := []u8{}
	pad_msg << pad16(aad)
	pad_msg << pad16(ciphertext)
	binary.little_endian_put_u64(mut b8, u64(aad.len))
	pad_msg << b8
	binary.little_endian_put_u64(mut b8, u64(ciphertext.len))
	pad_msg << b8

	// update Poly1305 state with this padmsg
	mut po := poly1305.new(polykey)!
	po.update(pad_msg)
	mut tag := []u8{len: chacha20poly1305.tag_size}
	po.finish(mut tag)

	// add this tag to ciphertext
	ciphertext << tag

	return ciphertext
}

fn (c Chacha20Poly1305) decrypt(ciphertext []u8, nonce []u8, aad []u8) ![]u8 {
	if nonce.len != c.nonce_size() {
		return error('chacha20poly1305: unmatching nonce size')
	}
	if u64(ciphertext.len) > (u64(1) << 38) - 48 {
		return error('chacha20poly1305: ciphertext too large')
	}
	return c.decrypt_generic(ciphertext, nonce, aad)
}

fn (c Chacha20Poly1305) decrypt_generic(ciphertext []u8, nonce []u8, aad []u8) ![]u8 {
	mut cs := chacha20.new_cipher(c.key, nonce)!

	// and then performing Chacha20 block function
	mut polykey := []u8{len: chacha20poly1305.key_size}
	cs.xor_key_stream(mut polykey, polykey)

	// Next, the ChaCha20 encryption function is called to encrypt the
	// plaintext, using the same key and nonce, and with the initial
	// counter set to 1.
	cs.set_counter(1)

	// Remember, ciphertext = plaintext + tag (overhead) bytes
	split_at := ciphertext.len - c.tag_size()
	scrambled := ciphertext[0..split_at]
	mac := ciphertext[split_at..]
	mut plaintext := []u8{len: scrambled.len}
	cs.xor_key_stream(mut plaintext, scrambled)

	// Finally, the Poly1305 function is called with the Poly1305 key
	// calculated above, and a message constructed as a concatenation of
	// the following:
	mut po := poly1305.new(polykey)!
	mut padmsg := []u8{}
	pad_to_16(mut padmsg, aad)
	pad_to_16(mut padmsg, scrambled)

	mut b8 := []u8{len: 8}
	binary.little_endian_put_u64(mut b8, u64(aad.len))
	pad_to_16(mut padmsg, b8)

	binary.little_endian_put_u64(mut b8, u64(scrambled.len))
	pad_to_16(mut padmsg, b8)

	// update Poly1305 state with this padmsg
	po.update(padmsg)
	mut tag := []u8{len: chacha20poly1305.tag_size}
	po.finish(mut tag)

	// Let's verify the authenticated tag
	if !poly1305.verify_tag(tag, polykey, plaintext) {
		return error('chacha20poly1305: authenticated tag is not match, ${mac} vs ${tag}')
	}

	return plaintext
}

fn pad_to_16(mut out []u8, b []u8) {
	if b.len % 16 == 0 {
		out << b
		return
	}
	pad := []u8{len: 16 - b.len % 16}
	out << b
	out << pad
}

// pad to 16 u8 block
fn pad16(x []u8) []u8 {
	mut buf := x.clone()
	if buf.len % 16 == 0 {
		return buf
	}
	pad_bytes := []u8{len: 16 - buf.len % 16, init: 0}
	buf << pad_bytes
	return buf
}

fn construct_mac_data(aad []u8, text []u8) []u8 {
	mut b8 := []u8{len: 8}
	mut out := []u8{}
	out << pad16(aad)
	out << pad16(text)
	binary.little_endian_put_u64(mut b8, u64(aad.len))
	out << b8
	binary.little_endian_put_u64(mut b8, u64(text.len))
	out << b8

	return out
}
