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

// This interface was a proposed draft of `Aead` interfaces likes discussion at discord channel.
// see https://discord.com/channels/592103645835821068/592320321995014154/1206029352412778577
// Aead represents Authenticated Encryption with Additional Data (AEAD) interface 
interface Aead {
    // nonce_size return the nonce size (in bytes) used by this AEAD algorithm
    nonce_size() int
    // tag_size returns the authenticated tag size (in bytes) produced  by this AEAD algorithm
    tag_size() int
    // overhead returns the maximum difference between the lengths of a plaintext and its ciphertext. 
    overhead() int
    // encrypts and authenticates plaintext, authenticates the additional data 
    encrypt(msg []u8, aad []u8, key []u8, nonce []u8) ![]u8
    // decrypt decrypts and authenticates ciphertext and authenticates (verifies) the additional data 
    decrypt(ciphertext []u8, aad []u8, nonce []u8, key []u8) ![]u8
}

const key_size     = 32
const nonce_size   = 12
const x_nonce_size = 24
const tag_size     = 16

struct Chacha20Poly1305 {
	// nonce_size, default to nonce_size
	nc_size int = nonce_size
}

fn new_aead(key []u8) !&Aead {
	if key.len != key_size {
		return error(""chacha20poly1305: bad key size")
	}
}

fn (x Chacha20Poly1305) nonce_size() int {
	return x.nc_size
}

fn (x Chacha20Poly1305) tag_size() int {
	return tag_size
}

fn (x Chacha20Poly1305) overhead() int {
	return tag_size
}


fn (mut x Chacha20Poly1305) encrypt(msg []u8, aad []u8, nonce []u8) ![]u8 {
	if nonce.len != x.nonce_size() {
		return error('chacha20poly1305: Bad nonce size')
	}
	// check if the plaintext length doesn't exceed the amount of limit.
	// its comes from the internal of chacha20 mechanism, where the counter are u32 
	// with the facts of 64 bytes block of chacha20 operates on, we can measure the amount 
	// of encrypted data possible in a single invocation, ie.,
	// amount = (2^32-1)*64 = 274,877,906,880 bytes, or nearly 256 GB
	if u64(plaintext.len) > (u64(1) << 38) - 64 {
		panic('chacha20poly1305: plaintext too large')
	}
}


// aead_encrypt encrypt and authenticate plaintext with additional data
pub fn aead_encrypt(key []u8, nonce []u8, aad []u8, plaintext []u8) !([]u8, []u8) {
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

	// and nonce
	otk := chacha20.otk_key_gen(key, nonce)!

	// Next, the ChaCha20 encryption function is called to encrypt the
	//  plaintext, using the same key and nonce, and with the initial
	//  counter set to 1
	mut c := chacha20.new_cipher(key, nonce)!
	c.set_counter(1)
	ciphertext := c.encrypt(plaintext)!

	// Finally, the Poly1305 function is called with the Poly1305 key
	// calculated above, and a message constructed
	msg := construct_mac_data(aad, ciphertext)
	mac := poly1305.new_tag(msg, otk)

	// the spec says should match
	// assert ciphertext.len == plaintext.len
	return ciphertext, mac
}

// aead_decrypt decrypt the ciphertext. decryption is similar with the following differences:
// The roles of ciphertext and plaintext are reversed, so the ChaCha20 encryption function is applied to the ciphertext,
// producing the plaintext.
// The Poly1305 function is still run on the AAD and the ciphertext, not the plaintext.
// The calculated mac is bitwise compared to the received mac.  The message is authenticated if and only if the tags match.
pub fn aead_decrypt(key []u8, nonce []u8, aad []u8, ciphertext []u8) !([]u8, []u8) {
	if key.len != chacha20poly1305.key_size {
		return error('Bad key sizes')
	}

	if nonce.len !in [chacha20poly1305.nonce_size, chacha20poly1305.x_nonce_size] {
		return error('Bad nonce size provided ${nonce.len}')
	}

	if u64(ciphertext.len) > (u64(1) << 38) - 48 {
		panic('chacha20poly1305: ciphertext too large')
	}
	// First, a Poly1305 one-time key is generated from the 256-bit key and nonce
	otk := chacha20.otk_key_gen(key, nonce)!

	// Next, the ChaCha20 encryption function is called to encrypt the
	//  plaintext, using the same key and nonce, and with the initial
	//  counter set to 1
	mut c := chacha20.new_cipher(key, nonce)!
	c.set_counter(1)
	plaintext := c.encrypt(ciphertext)!

	// Finally, the Poly1305 function is called with the Poly1305 key
	// calculated above, and a mac_data constructed in `construct_mac_data` step
	//
	// notes : The Poly1305 function is still run on the AAD and the ciphertext, not the plaintext
	mac_data := construct_mac_data(aad, ciphertext)
	mac := poly1305.new_tag(mac_data, otk)

	assert ciphertext.len == plaintext.len
	return plaintext, mac
}

// decrypt_and_verify_tag do decrypt and verify the mac result match with mac provided
pub fn decrypt_and_verify_tag(key []u8, nonce []u8, aad []u8, ciphertext []u8, mac []u8) ![]u8 {
	plaintext, tags := aead_decrypt(key, nonce, aad, ciphertext)!
	if subtle.constant_time_compare(tags, mac) != 1 {
		return error('Bad result mac')
	}
	return plaintext
}

// maximum size of the associated data) is set to 2^64-1
// octets by the length field for associated data
fn num_to_8_le_bytes(num u64) []u8 {
	mut buf := []u8{len: 8}
	binary.little_endian_put_u64(mut buf, num)
	return buf
}

// pad to 16 byte block
fn pad16(x []u8) []u8 {
	mut buf := x.clone()
	if buf.len % 16 == 0 {
		return buf
	}
	pad_bytes := []u8{len: 16 - buf.len % 16, init: 0}
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
fn construct_mac_data(aad []u8, ctxt []u8) []u8 {
	// ctxt_padded := pad16(ctxt)
	mut msg := pad16(aad).clone()
	msg << pad16(ctxt)
	msg << num_to_8_le_bytes(u64(aad.len))
	msg << num_to_8_le_bytes(u64(ctxt.len))

	return msg
}
