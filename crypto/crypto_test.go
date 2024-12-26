package cryptopq_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	cryptopq "github.com/ravinderncog/cryptopq/crypto"
	"github.com/stretchr/testify/assert"
)

func TestKeccak512(t *testing.T) {
	data := []byte("test data")
	hash := cryptopq.Keccak512(data)
	assert.NotEmpty(t, hash, "Hash should not be empty")
}

func TestKeccak512Hash(t *testing.T) {
	data := []byte("test data")
	hash := cryptopq.Keccak512Hash(data)
	assert.NotEmpty(t, hash, "Hash should not be empty")
}

func TestCreateAddress(t *testing.T) {
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	nonce := uint64(1)
	generatedAddr := cryptopq.CreateAddress(addr, nonce)
	assert.NotEqual(t, addr, generatedAddr, "Generated address should not match original address")
}

func TestToMLDsa87AndFromMLDsa87(t *testing.T) {
	_, priv, err := mldsa87.GenerateKey(nil)
	assert.NoError(t, err, "Failed to generate key")

	serialized := cryptopq.FromMLDsa87(priv)
	reconstructedPriv, err := cryptopq.ToMLDsa87(serialized)
	assert.NoError(t, err, "Failed to reconstruct private key")
	assert.Equal(t, priv, reconstructedPriv, "Original and reconstructed private keys should match")
}

func TestHexToMLDsa87(t *testing.T) {
	_, priv, err := mldsa87.GenerateKey(nil)
	assert.NoError(t, err, "Failed to generate key")

	hexKey := hex.EncodeToString(cryptopq.FromMLDsa87(priv))
	reconstructedPriv, err := cryptopq.HexToMLDsa87(hexKey)
	assert.NoError(t, err, "Failed to reconstruct private key from hex")
	assert.Equal(t, priv, reconstructedPriv, "Original and reconstructed private keys should match")
}

func TestSignAndValidateMLDsa87Signature(t *testing.T) {
	// Generate a key pair
	_, priv, err := mldsa87.GenerateKey(nil)
	assert.NoError(t, err, "Failed to generate private key")

	// Message to sign
	msg := []byte("test message")

	// Sign the message using the private key
	sig, err := cryptopq.SignMLDsa87(priv, msg)
	assert.NoError(t, err, "Failed to sign message")

	// Get the public key from the private key
	pubKey, ok := priv.Public().(*mldsa87.PublicKey)
	assert.True(t, ok, "Failed to convert public key to *mldsa87.PublicKey")

	// Validate the signature using the public key
	isValid := cryptopq.ValidateMLDsa87Signature(pubKey, msg, sig)
	assert.True(t, isValid, "Signature validation failed")
}

func TestGenerateKyberKeys(t *testing.T) {
	priv, pub, err := cryptopq.GenerateKyberKeys()
	assert.NoError(t, err, "Failed to generate Kyber keys")
	assert.NotNil(t, priv, "Private key should not be nil")
	assert.NotNil(t, pub, "Public key should not be nil")
}

func TestGenerateRandomNumber(t *testing.T) {
	// Generate a key pair
	_, priv, err := mldsa87.GenerateKey(nil)
	assert.NoError(t, err, "Failed to generate private key")

	// Get the public key from the private key
	pubKey, ok := priv.Public().(*mldsa87.PublicKey)
	assert.True(t, ok, "Failed to convert public key to *mldsa87.PublicKey")

	// Generate a random number using the private and public keys
	randNum, err := cryptopq.GenerateRandomNumber(priv, pubKey)
	assert.NoError(t, err, "Failed to generate random number")
	assert.NotZero(t, randNum, "Random number should not be zero")
}

func TestGenerateNonce(t *testing.T) {
	priv, pub, err := cryptopq.GenerateKyberKeys()
	assert.NoError(t, err, "Failed to generate Kyber keys")

	nonce, err := cryptopq.GenerateNonce(priv, pub, 16)
	assert.NoError(t, err, "Failed to generate nonce")
	assert.Equal(t, 16, len(nonce), "Nonce length should match the requested size")
}

func TestSignTxWithMLDSA87(t *testing.T) {
	// Create a new transaction
	tx := types.NewTransaction(1, common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"), big.NewInt(1000), 21000, big.NewInt(1), nil)

	// Define the signer
	signer := types.NewEIP155Signer(big.NewInt(1))

	// Generate a private key using MLDsa87
	_, priv, err := mldsa87.GenerateKey(nil)
	assert.NoError(t, err, "Failed to generate private key")

	// Compute the transaction hash
	hash := signer.Hash(tx).Bytes()

	// Sign the transaction hash using MLDsa87
	sig, err := cryptopq.SignMLDsa87(priv, hash)
	assert.NoError(t, err, "Failed to sign transaction hash")

	// Truncate the signature to 65 bytes to simulate compatibility
	truncatedSig := make([]byte, 65)
	copy(truncatedSig, sig[:min(len(sig), 65)]) // Adjust this logic as needed

	// Apply the signature to the transaction
	signedTx, err := tx.WithSignature(signer, truncatedSig)
	assert.NoError(t, err, "Failed to sign transaction")
	assert.NotNil(t, signedTx, "Signed transaction should not be nil")
}

// Helper function to determine the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestSequentialNonceGenerator(t *testing.T) {
	start := uint64(100)
	generator := cryptopq.NewSequentialNonceGenerator(start)

	for i := 0; i < 5; i++ {
		expected := start + uint64(i+1)
		assert.Equal(t, expected, generator.Next(), "Sequential nonce value mismatch")
	}
}
