package main

// SealedHeader represents the JSON metadata (first line of output)
type SealedHeader struct {
	Version   string    `json:"version"`
	Algorithm string    `json:"algorithm"`
	Format    string    `json:"format"` // "binary" or "base64"
	KDF       KDFParams `json:"kdf"`
}

// KDFParams contains Argon2id parameters for key derivation
type KDFParams struct {
	Algorithm string `json:"algorithm"`
	Salt      string `json:"salt"`
	Time      uint32 `json:"time"`
	Memory    uint32 `json:"memory"`
	Threads   uint8  `json:"threads"`
	KeyLen    uint32 `json:"keylen"`
}
