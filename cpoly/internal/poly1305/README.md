# Poly1305 Message Authentication Code (MAC) in V language
--------------------------------------------------------

This is `poly1305` message authentication code (MAC) module in V language
ported from Rust `poly1305`. Its implements Poly1305 one-time message authentication code as
specified in https://cr.yp.to/mac/poly1305-20050329.pdf.

Poly1305 is a fast, one-time authentication function. It is infeasible for an
attacker to generate an authenticator for a message without the key. 
<b>As a note,</b> a key must only be used for a single message. 
Authenticating two different messages with the same key allows an attacker 
to forge authenticators for other messages with the same key.



NOTES!!
-------
Arithmatic for integer  of underlying poly1305 operations need to be checked. 
There are some of Rust `wrapping_add` and `wrapping_sub` semantics that 
are need to be checked on V.