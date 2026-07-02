// Generates a P-256 test vector with Apple CryptoKit so the Rust engine can
// prove byte-for-byte compatibility with the Swift app's key handling.
//
// Run:  swift scripts/gen_cryptokit_fixture.swift
//
// Emits the private scalar (rawRepresentation, 32 bytes), the compressed SEC1
// public key (33 bytes), the fixed message, and an ECDSA/SHA-256 signature
// (rawRepresentation, 64 bytes r‖s) as hex. Paste the values into the
// `cryptokit_cross_language_vector` test in src/identity.rs.

import CryptoKit
import Foundation

func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

// The message the signature covers. Keep this in sync with the Rust test.
let message = Data("proxy-node-server cross-language fixture".utf8)

let privateKey = P256.Signing.PrivateKey()
let publicKey = privateKey.publicKey
let signature = try privateKey.signature(for: message)

print("message_utf8:    proxy-node-server cross-language fixture")
print("private_raw:     \(hex(privateKey.rawRepresentation))")
print("public_sec1_c:   \(hex(publicKey.compressedRepresentation))")
print("signature_raw:   \(hex(signature.rawRepresentation))")
