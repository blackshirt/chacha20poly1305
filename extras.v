module chacha20poly1305

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


// maximum size of the associated data) is set to 2^64-1
// octets by the length field for associated data
fn num_to_8_le_bytes(num u64) []u8 {
	mut buf := []u8{len: 8}
	binary.little_endian_put_u64(mut buf, num)
	return buf
}

fn write_u64(mut p poly1305.Poly1305, n u64) {
	mut buf := []u8{len: 8}
	binary.little_endian_put_u64(mut buf, n)
	p.update(buf)
}

fn write_with_padding(mut p poly1305.Poly1305, b []u8) {
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
		head = input[..total]
	} else {
		head = make([]u8{}, total)
		copy(head, input)
	}
	tail = head[input.len..]
	return
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


*/
