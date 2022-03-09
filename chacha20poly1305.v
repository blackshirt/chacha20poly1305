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
import chacha20
import poly1305

const (
	key_size     = 32
	nonce_size   = 12
	x_nonce_size = 24
)

struct Chacha20Poly1305 {
	key []byte
}

// new_chacha20poly1305 creates Chacha20Poly1305 instances from key
pub fn new_chacha20poly1305(key []byte) ?&Chacha20Poly1305 {
	if key.len != chacha20poly1305.key_size {
		return error('Bad key sizes')
	}
	mut c := &Chacha20Poly1305{
		key: key
	}
	return c
}

struct AeadResult {
	txt []byte
	tag []byte
}

// message returns underlying message in the context of ciphertext or plaintext
pub fn (r AeadResult) message() []byte {
	return r.txt
}

// tag return tag result of encrypt or decrypt
pub fn (r AeadResult) tag() []byte {
	return r.tag
}

// encrypt encrypts the plaintext with provided nonce and additional data aad and return result
pub fn (c &Chacha20Poly1305) encrypt(plaintext []byte, nonce []byte, aad []byte) ?AeadResult {
	if nonce.len !in [chacha20poly1305.nonce_size, chacha20poly1305.x_nonce_size] {
		return error('Bad nonce size')
	}
	ciphertext, tag := aead_encrypt(plaintext, c.key, nonce, aad) ?
	return AeadResult{
		txt: ciphertext
		tag: tag
	}
}

// decrypt decrypts ciphertext with provided nonce and additional data aad.
pub fn (c &Chacha20Poly1305) decrypt(ciphertext []byte, nonce []byte, aad []byte) ?AeadResult {
	plaintext, tag := aead_decrypt(ciphertext, c.key, nonce, aad) ?

	return AeadResult{
		txt: plaintext
		tag: tag
	}
}

// decrypt_and_verify decrypts the ciphertext and verify the mac match with result tag and return error otherwise.
pub fn (c &Chacha20Poly1305) decrypt_and_verify(ciphertext []byte, nonce []byte, aad []byte, mac []byte) ?AeadResult {
	res := c.decrypt(ciphertext, nonce, aad) ?
	if subtle.constant_time_compare(res.tag, mac) != 1 {
		return error('Bad result tag')
	}
	return res
}

// aead_encrypt encrypt and authenticate plaintext with additional data
fn aead_encrypt(plaintext []byte, key []byte, nonce []byte, aad []byte) ?([]byte, []byte) {
	if key.len != chacha20poly1305.key_size {
		return error('Bad key sizes')
	}
	if nonce.len !in [chacha20poly1305.nonce_size, chacha20poly1305.x_nonce_size] {
		return error('Bad nonce size')
	}
	// check plaintext len doesn't exceed
	if u64(plaintext.len) > (u64(1) << 38) - 64 {
		panic('chacha20poly1305: plaintext too large')
	}
	// First, a Poly1305 one-time key is generated from the 256-bit key
	//  and nonce
	otk := chacha20.otk_key_gen(key, nonce) ?

	// Next, the ChaCha20 encryption function is called to encrypt the
	//  plaintext, using the same key and nonce, and with the initial
	//  counter set to 1
	mut c := chacha20.new_cipher(key, nonce) ?
	c.set_counter(1)
	ciphertext := c.encrypt(plaintext) ?

	// Finally, the Poly1305 function is called with the Poly1305 key
	// calculated above, and a message constructed
	msg := construct_mac_data(aad, ciphertext)
	tag := poly1305.new_tag(msg, otk)

	// the spec says should match
	// assert ciphertext.len == plaintext.len
	return ciphertext, tag
}

// aead_decrypt decrypt the ciphertext. decryption is similar with the following differences:
// The roles of ciphertext and plaintext are reversed, so the ChaCha20 encryption function is applied to the ciphertext,
// producing the plaintext.
// The Poly1305 function is still run on the AAD and the ciphertext, not the plaintext.
// The calculated tag is bitwise compared to the received tag.  The message is authenticated if and only if the tags match.
fn aead_decrypt(ciphertext []byte, key []byte, nonce []byte, aad []byte) ?([]byte, []byte) {
	if key.len != chacha20poly1305.key_size {
		return error('Bad key sizes')
	}

	if nonce.len !in [chacha20poly1305.nonce_size, chacha20poly1305.x_nonce_size] {
		return error('Bad nonce size provided $nonce.len')
	}

	if u64(ciphertext.len) > (u64(1) << 38) - 48 {
		panic('chacha20poly1305: ciphertext too large')
	}
	// First, a Poly1305 one-time key is generated from the 256-bit key and nonce
	otk := chacha20.otk_key_gen(key, nonce) ?

	// Next, the ChaCha20 encryption function is called to encrypt the
	//  plaintext, using the same key and nonce, and with the initial
	//  counter set to 1
	mut c := chacha20.new_cipher(key, nonce) ?
	c.set_counter(1)
	plaintext := c.encrypt(ciphertext) ?

	// Finally, the Poly1305 function is called with the Poly1305 key
	// calculated above, and a mac_data constructed in `construct_mac_data` step
	//
	// notes : The Poly1305 function is still run on the AAD and the ciphertext, not the plaintext
	mac_data := construct_mac_data(aad, ciphertext)
	tag := poly1305.new_tag(mac_data, otk)

	assert ciphertext.len == plaintext.len
	return plaintext, tag
}

// decrypt_and_verify_tag do decrypt and verify the tag result match with tag provided
fn decrypt_and_verify_tag(ciphertext []byte, key []byte, nonce []byte, aad []byte, tag []byte) ?[]byte {
	plaintext, mac := aead_decrypt(ciphertext, key, nonce, aad) ?
	if subtle.constant_time_compare(tag, mac) != 1 {
		return error('Bad result tag')
	}
	return plaintext
}

// maximum size of the associated data) is set to 2^64-1
// octets by the length field for associated data
fn num_to_8_le_bytes(num u64) []byte {
	mut buf := []byte{len: 8}
	binary.little_endian_put_u64(mut buf, num)
	return buf
}

// pad to 16 byte block
fn pad16(x []byte) []byte {
	mut buf := x.clone()
	if buf.len % 16 == 0 {
		return buf
	}
	pad_bytes := []byte{len: 16 - buf.len % 16, init: 0}
	buf << pad_bytes
	return buf
}

// message mac data constructed as a concatenation of the following:
//    *  The AAD
//    *  padding1 -- the padding is up to 15 zero bytes, and it brings
//       the total length so far to an integral multiple of 16.  If the
//       length of the AAD was already an integral multiple of 16 bytes,
//       this field is zero-length.
//
//    *  The ciphertext
//    *  padding2 -- the padding is up to 15 zero bytes, and it brings
//       the total length so far to an integral multiple of 16.  If the
//       length of the ciphertext was already an integral multiple of 16
//       bytes, this field is zero-length.
//    *  The length of the additional data in octets (as a 64-bit
//       little-endian integer).
//    *  The length of the ciphertext in octets (as a 64-bit little-
//       endian integer).
fn construct_mac_data(aad []byte, ctxt []byte) []byte {
	// ctxt_padded := pad16(ctxt)
	mut msg := pad16(aad).clone()
	msg << pad16(ctxt)
	msg << num_to_8_le_bytes(u64(aad.len))
	msg << num_to_8_le_bytes(u64(ctxt.len))

	return msg
}
