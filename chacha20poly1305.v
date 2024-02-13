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

// encrypt
pub fn (c Chacha20Poly1305) encrypt(plaintext []u8, nonce []u8, aad []u8) ![]u8 {
	// makes sure if the nonce length is matching with internal nonce size
	if nonce.len != c.nonce_size() {
		return error('chacha20poly1305: unmatching nonce size')
	}
	// check if the plaintext length doesn't exceed the amount of limit.
	// its comes from the internal of chacha20 mechanism, where the counter are u32
	// with the facts of chacha20 operates on 64 bytes block, we can measure the amount
	// of encrypted data possible in a single invocation, ie.,
	// amount = (2^32-1)*64 = 274,877,906,880 bytes, or nearly 256 GB
	if u64(plaintext.len) > (u64(1) << 38) - 64 {
		panic('chacha20poly1305: plaintext too large')
	}
	if aad.len > max_u64 {
		return error('chacha20poly1305: something bad in your aad')
	}
	return c.encrypt_generic(plaintext, nonce, aad)
}

// encrypt_generic encrypts plaintext along with nonce and additional data
fn (c Chacha20Poly1305) encrypt_generic(plaintext []u8, nonce []u8, aad []u8) ![]u8 {
	// First, generates a Poly1305 one-time key from the 256-bit key
	// and given nonce. Actually its generates by performing ChaCha20 key stream function,
	// and take the first 32 bytes as a one-time key for Poly1305 from 64 bytes results.
	// see https://datatracker.ietf.org/doc/html/rfc8439#section-2.6
	mut polykey := []u8{len: chacha20poly1305.key_size}
	mut s := chacha20.new_cipher(c.key, nonce)!
	s.xor_key_stream(mut polykey, polykey)

	// Next, the ChaCha20 encryption function is called to encrypt the plaintext,
	// using the same key and nonce, and with the initial ChaCha20 counter set to 1.
	mut ciphertext := []u8{len: plaintext.len}
	s.set_counter(1)
	s.xor_key_stream(mut ciphertext, plaintext)

	// Finally, the Poly1305 function is called with the Poly1305 key
	// calculated above, and a message constructed as descibed in
	// https://datatracker.ietf.org/doc/html/rfc8439#section-2.8
	mut constructed_msg := []u8{}
	poly1305_construct_msg(mut constructed_msg, aad, ciphertext)

	// Lets creates Poly1305 instance with one-time key generates in above step,
	// updates Poly1305 state with this constructed_msg and finally generates tag.
	mut tag := []u8{len: chacha20poly1305.tag_size}
	mut po := poly1305.new(polykey)!
	po.update(constructed_msg)
	po.finish(mut tag)

	// add this tag to ciphertext output
	ciphertext << tag

	return ciphertext
}

// decrypt decrypts ciphertext along with provided nonce and additional data.
// Decryption is similar with the encryption processs with slight differences in:
// The roles of ciphertext and plaintext are reversed, so the ChaCha20 encryption
// function is applied to the ciphertext, producing the plaintext.
// The Poly1305 function is still run on the AAD and the ciphertext, not the plaintext.
// The calculated mac is bitwise compared to the received mac.
// The message is authenticated if and only if the tags match.
fn (c Chacha20Poly1305) decrypt(ciphertext []u8, nonce []u8, aad []u8) ![]u8 {
	if nonce.len != c.nonce_size() {
		return error('chacha20poly1305: unmatching nonce size')
	}
	// ciphertext max = plaintext max length  + tag length
	// ie, (2^32-1)*64 + overhead = (u64(1) << 38) - 64 + 16 = 274,877,906,896 octets.
	if u64(ciphertext.len) > (u64(1) << 38) - 48 {
		return error('chacha20poly1305: ciphertext too large')
	}
	return c.decrypt_generic(ciphertext, nonce, aad)
}

fn (c Chacha20Poly1305) decrypt_generic(ciphertext []u8, nonce []u8, aad []u8) ![]u8 {
	// generates poly1305 one-time key for later calculation
	mut polykey := []u8{len: chacha20poly1305.key_size}
	mut s := chacha20.new_cipher(c.key, nonce)!
	s.xor_key_stream(mut polykey, polykey)

	// Remember, ciphertext is concatenation of associated cipher output plus tag (mac) bytes
	cipherout := ciphertext[0..ciphertext.len - c.tag_size()]
	mac := ciphertext[ciphertext.len - c.tag_size()..]

	mut plaintext := []u8{len: cipherout.len}
	s.set_counter(1)
	// doing reverse encrypt on cipher output part produces plaintext
	s.xor_key_stream(mut plaintext, cipherout)

	// authenticated messages part
	mut constructed_msg := []u8{}
	poly1305_construct_msg(mut constructed_msg, aad, cipherout)

	mut tag := []u8{len: chacha20poly1305.tag_size}
	mut po := poly1305.new(polykey)!
	po.update(constructed_msg)
	po.finish(mut tag)

	// lets verify if received mac is matching with calculated tag,
	// return error on fail
	if subtle.constant_time_compare(mac, tag) != 1 {
		return error('chacha20poly1305: unmatching tag')
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

// poly1305_construct_msg constructs message for poly1305 function.
// The message constructed as a concatenation of the following:
// 	*  padded to multiple of 16 bytes block of the additional data bytes
// 	*  padded to multiple of 16 bytes block of the ciphertext (or plaintext) bytes
// 	*  The length of the additional data in octets (as a 64-bit little-endian integer).
// 	*  The length of the ciphertext (or plaintext) in octets (as a 64-bit little-endian integer).
fn poly1305_construct_msg(mut out []u8, aad []u8, bytes []u8) {
	mut b8 := []u8{len: 8}
	out << pad16(aad)
	out << pad16(bytes)
	binary.little_endian_put_u64(mut b8, u64(aad.len))
	out << b8
	binary.little_endian_put_u64(mut b8, u64(bytes.len))
	out << b8
}
