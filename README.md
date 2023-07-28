# chacha20poly1305
------------------

Chacha20Poly1305 Authenticated Encryption with Additional Data (AEAD) module for V Language

This module provides authenticated encryption with additional data (AEAD) algorithm in V Language.
Its backed by `chacha20` (and `xchacha20`) symetric key stream cipher encryption 
and `poly1305` message authentication code (MAC) included in submodules in the same repository.

# module cpoly




## Contents
- [Constants](#Constants)
- [aead_encrypt](#aead_encrypt)
- [decrypt_and_verify_tag](#decrypt_and_verify_tag)
- [aead_decrypt](#aead_decrypt)

## Constants
```v
const (
	key_size     = chacha20.key_size
	nonce_size   = 12
	x_nonce_size = 24
	tag_size     = poly1305.tag_size
)
```


[[Return to contents]](#Contents)

## aead_encrypt
```v
fn aead_encrypt(key []u8, nonce []u8, aad []u8, plaintext []u8) !([]u8, []u8)
```

aead_encrypt encrypt and authenticate plaintext with additional data

[[Return to contents]](#Contents)

## decrypt_and_verify_tag
```v
fn decrypt_and_verify_tag(key []u8, nonce []u8, aad []u8, ciphertext []u8, mac []u8) ![]u8
```

decrypt_and_verify_tag do decrypt and verify the mac result match with mac provided

[[Return to contents]](#Contents)

## aead_decrypt
```v
fn aead_decrypt(key []u8, nonce []u8, aad []u8, ciphertext []u8) !([]u8, []u8)
```

aead_decrypt decrypt the ciphertext. decryption is similar with the following differences: The roles of ciphertext and plaintext are reversed, so the ChaCha20 encryption function is applied to the ciphertext,
producing the plaintext.  
The Poly1305 function is still run on the AAD and the ciphertext, not the plaintext.  
The calculated mac is bitwise compared to the received mac.  The message is authenticated if and only if the tags match.  

[[Return to contents]](#Contents)

#### Powered by vdoc. Generated on: 28 Jul 2023 18:58:51
