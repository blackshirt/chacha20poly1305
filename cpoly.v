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
module cpoly
