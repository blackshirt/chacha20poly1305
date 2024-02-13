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
    encrypt(mut dst []u8, plaintext []u8, nonce []u8, aad []u8) ![]u8
    // decrypt decrypts and authenticates (verifies) the provided ciphertext along with a nonce, and  
	// associated data. If successful,  it returns the plaintext and appends the resulting plaintext to dst.
    decrypt(mut dst []u8, ciphertext []u8, nonce []u8, aad []u8) ![]u8
}

const key_size     = 32
const nonce_size   = 12
const x_nonce_size = 24
const tag_size     = 16

struct Chacha20Poly1305 {
	key 	[]u8 	= []u8{len: key_size}
	ncsize 	int 	= nonce_size
}

fn new(key []u8, ncsize int) !&AEAD {
	if key.len != key_size {
		return error("chacha20poly1305: bad key size")
	}
	if ncsize != nonce_size && ncsize != x_nonce_size {
		return error("chacha20poly1305: bad nonce size supplied, its should 12 or 24")
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
	return tag_size
}

fn (c Chacha20Poly1305) overhead() int {
	return tag_size
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
	// First, generates the Poly1305 Key Using ChaCha20 stream cipher.
	// see https://datatracker.ietf.org/doc/html/rfc8439#section-2.6
	// creates ChaCha20 cipher with key from this Chacha20Poly1305 instance 
	// and provided nonce.
	mut cs := chacha20.new_cipher(c.key, nonce)!
	
	// and then performing Chacha20 block function 
	mut polykey := []u8{len: key_size}
	cs.xor_key_stream(mut polykey, polykey)

	// Next, the ChaCha20 encryption function is called to encrypt the
	// plaintext, using the same key and nonce, and with the initial
	// counter set to 1.
	cs.set_counter(1)
	mut ciphertext := []u8{len: plaintext.len}
	cs.xor_key_stream(mut ciphertext, plaintext)

	// Finally, the Poly1305 function is called with the Poly1305 key
	// calculated above, and a message constructed as a concatenation of
	// the following:
	mut po := poly1305.new(polykey)!
	mut padmsg := []u8{}
	pad_to_16(mut padmsg, aad)
	pad_to_16(mut padmsg, ciphertext)
	
	mut b8 := []u8{len: 8}
	binary.little_endian_put_u64(mut b8, u64(aad.len))
	pad_to_16(mut padmsg, b8)

	binary.little_endian_put_u64(mut b8, u64(ciphertext.len))
	pad_to_16(mut padmsg, b8)
	
	// update Poly1305 state with this padmsg
	po.update(padmsg)
	mut tag := []u8{len: tag_size)
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
	return c.decrypy_generic(ciphertext, nonce, aad)
}


fn (c Chacha20Poly1305) decrypt_generic(ciphertext []u8, nonce []u8, aad []u8) ![]u8 {
	mut cs := chacha20.new_cipher(c.key, nonce)!
	
	// and then performing Chacha20 block function 
	mut polykey := []u8{len: key_size}
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
	mut tag := []u8{len: tag_size)
	po.finish(mut tag)

	// Let's verify the authenticated tag
	if !poly1305.verify_tag(mac, c.key, plaintext) {
		return error("chacha20poly1305: authenticated tag is not match")
	}

	return plaintext
}

/*
// encrypt encrypts and authenticate plaintext with additional data
fn encrypt(plaintext []u8, key []u8, nonce []u8, aad []u8) ![]u8 {
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
	return encrypt_generic(plaintext, key, nonce, aad)
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
	// First, generates the Poly1305 Key Using ChaCha20
	// see https://datatracker.ietf.org/doc/html/rfc8439#section-2.6
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

*/

// maximum size of the associated data) is set to 2^64-1
// octets by the length field for associated data
fn num_to_8_le_bytes(num u64) []u8 {
	mut buf := []u8{len: 8}
	binary.little_endian_put_u64(mut buf, num)
	return buf
}

fn write_u64(mut p &poly1305.Poly1305, n u64) {
	mut buf := []u8{len: 8}
	binary.little_endian_put_u64(mut buf, n)
	p.update(buf)
}

fn write_with_padding(mut p &poly1305.Poly1305, b []u8) {
	p.update(b)
	rem := len(b) % 16
	if rem != 0 {
		buf := [16]u8{}
		padlen := 16 - rem
		p.update(buf[..padlen])
	}
}

fn take_slice_for_append(input []u8, n int) ([]u8, []u8) {
	total := input.len + n
	if input.cap >= total {
		head = input[:total]
	} else {
		head = make([]u8, total)
		copy(head, input)
	}
	tail = head[input.len:]
	return
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
