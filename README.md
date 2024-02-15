# chacha20poly1305
------------------

Chacha20Poly1305 Authenticated Encryption with Additional Data (AEAD) module for V Language

This module provides authenticated encryption with additional data (AEAD) algorithm in V Language.
Its backed by `chacha20` (and `xchacha20`) symetric key stream cipher encryption 
and `poly1305` message authentication code (MAC) included in submodules in the same repository.

>[!NOTE]
>This module was made as an public archive. This module was upstreamed and merged to experimental
>`x.crypto.chacha20poly1305` module of the v standard vlib recently,
>so just use it instead. Improvement would be done on there.
