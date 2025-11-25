package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id fixed parameters
	Argon2Threads = 4
	Argon2KeyLen  = 32 // 256 bits for AES-256
	SaltLen       = 16
)

// deriveKey derives an encryption key from a passphrase using Argon2id
func deriveKey(passphrase, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return argon2.IDKey(passphrase, salt, time, memory, threads, keyLen)
}

// createKeysetFromKey creates a Tink keyset handle from a raw key
func createKeysetFromKey(key []byte) (*keyset.Handle, error) {
	// Tink keyset JSON format for AES-GCM-HKDF streaming key
	keyValue := base64.StdEncoding.EncodeToString(buildAesGcmHkdfStreamingKeyValue(key))

	keysetJSON := fmt.Sprintf(`{
		"primaryKeyId": 1,
		"key": [{
			"keyData": {
				"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey",
				"keyMaterialType": "SYMMETRIC",
				"value": "%s"
			},
			"outputPrefixType": "RAW",
			"keyId": 1,
			"status": "ENABLED"
		}]
	}`, keyValue)

	return insecurecleartextkeyset.Read(
		keyset.NewJSONReader(strings.NewReader(keysetJSON)),
	)
}

// buildAesGcmHkdfStreamingKeyValue builds the protobuf-encoded key value
func buildAesGcmHkdfStreamingKeyValue(key []byte) []byte {
	// Protobuf encoding for AesGcmHkdfStreamingKey
	// See: https://github.com/tink-crypto/tink/blob/master/proto/aes_gcm_hkdf_streaming.proto

	segmentSize := uint32(1048576) // 1MB
	derivedKeySize := uint32(32)   // AES-256
	hkdfHashType := uint32(3)      // SHA256

	// Build params submessage
	params := []byte{}
	params = append(params, 0x08)                            // field 1, varint
	params = append(params, encodeVarint(segmentSize)...)    // ciphertext_segment_size
	params = append(params, 0x10)                            // field 2, varint
	params = append(params, encodeVarint(derivedKeySize)...) // derived_key_size
	params = append(params, 0x18)                            // field 3, varint
	params = append(params, encodeVarint(hkdfHashType)...)   // hkdf_hash_type

	// Build main message
	result := []byte{}
	result = append(result, 0x08)              // field 1 (version), varint
	result = append(result, 0x00)              // version = 0
	result = append(result, 0x12)              // field 2 (params), length-delimited
	result = append(result, byte(len(params))) // params length
	result = append(result, params...)         // params
	result = append(result, 0x1a)              // field 3 (key_value), length-delimited
	result = append(result, byte(len(key)))    // key length
	result = append(result, key...)            // key

	return result
}

func encodeVarint(v uint32) []byte {
	var buf []byte
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	buf = append(buf, byte(v))
	return buf
}
