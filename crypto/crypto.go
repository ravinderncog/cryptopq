package cryptopq

import (
	"bufio"
	"crypto"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// SignatureLength indicates the byte length required to carry a signature with recovery id.
const SignatureLength = 64 + 1 // 64 bytes MLDsa87 signature + 1 byte recovery id

// DigestLength sets the signature digest exact length
const DigestLength = 32

var errInvalidPubkey = errors.New("invalid MLDsa87 public key")

// PrivateKey is an alias for mldsa87.PrivateKey
type PrivateKey = mldsa87.PrivateKey

// PublicKey is an alias for mldsa87.PublicKey
type PublicKey = mldsa87.PublicKey

// KeccakState wraps sha3.state
type KeccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

func NewKeccakState() KeccakState {
	return sha3.NewLegacyKeccak512().(KeccakState)
}

func HashData(kh KeccakState, data []byte) (h common.Hash) {
	kh.Reset()
	kh.Write(data)
	kh.Read(h[:])
	return h
}

func Keccak512(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

/* func Keccak512Hash(data ...[]byte) (h common.Hash) {
	d := sha3.NewLegacyKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	d.Read(h[:])
	return h
} */

func Keccak512Hash(data ...[]byte) (h common.Hash) {
	d := sha3.NewLegacyKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	sum := d.Sum(nil) // Get the resulting hash
	copy(h[:], sum)   // Copy the first 32 bytes into h
	return h
}

func CreateAddress(b common.Address, nonce uint64) common.Address {
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
	return common.BytesToAddress(Keccak512(data)[12:])
}

func CreateAddress2(b common.Address, salt [32]byte, inithash []byte) common.Address {
	return common.BytesToAddress(Keccak512([]byte{0xff}, b.Bytes(), salt[:], inithash)[12:])
}

// ToMLDsa87 creates a private key with the given bytes.
func ToMLDsa87(d []byte) (*mldsa87.PrivateKey, error) {
	priv := new(mldsa87.PrivateKey)
	err := priv.UnmarshalBinary(d)
	if err != nil {
		return nil, errors.New("invalid MLDsa87 private key")
	}
	return priv, nil
}

func FromMLDsa87(priv *mldsa87.PrivateKey) []byte {
	b, _ := priv.MarshalBinary()
	return b
}

func UnmarshalPubkey(pub []byte) (*mldsa87.PublicKey, error) {
	var publicKey mldsa87.PublicKey
	err := publicKey.UnmarshalBinary(pub)
	if err != nil {
		return nil, errInvalidPubkey
	}
	return &publicKey, nil
}

func FromMLDsa87Pub(pub *mldsa87.PublicKey) []byte {
	b, _ := pub.MarshalBinary()
	return b
}

func HexToMLDsa87(hexkey string) (*mldsa87.PrivateKey, error) {
	b, err := hex.DecodeString(hexkey)
	if err != nil {
		return nil, err
	}
	return ToMLDsa87(b)
}

func LoadMLDsa87(file string) (*mldsa87.PrivateKey, error) {
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	r := bufio.NewReader(fd)
	buf := make([]byte, 64)
	n, err := readASCII(buf, r)
	if err != nil {
		return nil, err
	} else if n != len(buf) {
		return nil, fmt.Errorf("key file too short, want 64 hex characters")
	}
	if err := checkKeyFileEnd(r); err != nil {
		return nil, err
	}

	return HexToMLDsa87(string(buf))
}

func SaveMLDsa87(file string, key *mldsa87.PrivateKey) error {
	k := hex.EncodeToString(FromMLDsa87(key))
	return os.WriteFile(file, []byte(k), 0600)
}

/* func GenerateMLDsa87Key() (*mldsa87.PrivateKey, error) {
	_, sk, err := mldsa87.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return sk, nil // Return sk directly
} */

func GenerateMLDsa87Key() (*mldsa87.PublicKey, *mldsa87.PrivateKey, error) {
	pubk, sk, err := mldsa87.GenerateKey(DilithiumReader)
	if err != nil {
		return nil, nil, err
	}
	return pubk, sk, nil // sk is already a pointer to PrivateKey
}

/* func SignMLDsa87(priv *mldsa87.PrivateKey, hash []byte) ([]byte, error) {
	return mldsa87.Sign(priv, hash)
} */

// SignMLDsa87 signs the given message hash using the MLDsa87 private key.
func SignMLDsa87(priv *mldsa87.PrivateKey, msg []byte) ([]byte, error) {
	// Sign with nil SignerOpts since MLDsa87 does not support pre-hashed messages.
	return priv.Sign(DilithiumReader, msg, crypto.Hash(0))
}

/* func ValidateMLDsa87Signature(pub *mldsa87.PublicKey, hash []byte, sig []byte) bool {
	return mldsa87.Verify(pub, hash, sig)
} */

// ValidateMLDsa87Signature verifies the signature using the public key, hash, and signature.
func ValidateMLDsa87Signature(pub *mldsa87.PublicKey, msg []byte, sig []byte) bool {
	// Pass `nil` as the context string since we are not using any.
	return mldsa87.Verify(pub, msg, nil, sig)
}

func PubkeyToAddress(pub mldsa87.PublicKey) common.Address {
	pubBytes, _ := pub.MarshalBinary()
	return common.BytesToAddress(Keccak512(pubBytes)[12:])
}

/* func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
} */

func readASCII(buf []byte, r *bufio.Reader) (n int, err error) {
	for ; n < len(buf); n++ {
		buf[n], err = r.ReadByte()
		switch {
		case err == io.EOF || buf[n] < '!':
			return n, nil
		case err != nil:
			return n, err
		}
	}
	return n, nil
}

func checkKeyFileEnd(r *bufio.Reader) error {
	for i := 0; ; i++ {
		b, err := r.ReadByte()
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		case b != '\n' && b != '\r':
			return fmt.Errorf("invalid character %q at end of key file", b)
		case i >= 2:
			return errors.New("key file too long, want 64 hex characters")
		}
	}
}

func SignTxWithMLDSA87(tx *types.Transaction, signer types.Signer, key *mldsa87.PrivateKey) (*types.Transaction, error) {
	hash := signer.Hash(tx).Bytes()
	signature, err := SignMLDsa87(key, Keccak512(hash))
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(signer, signature)
}

/*
ToECDSA -->> ToMLDsa87
FromECDSA -->> FromMLDsa87
HexToECDSA -->> HexToMLDsa87
LoadECDSA -->> LoadMLDsa87
SaveECDSA -->> SaveMLDsa87
GenerateKey -->> GenerateMLDsa87Key
Sign -->> SignMLDsa87
*/
// DilithiumRNG is a thread-safe random number generator using Dilithium private keys.
type DilithiumRNG struct {
	privKey *mldsa87.PrivateKey
	lock    sync.Mutex
	counter uint64
}

// NewDilithiumRNG initializes a new DilithiumRNG instance with a provided Dilithium private key.
func NewDilithiumRNG() (*DilithiumRNG, error) {
	// Generate a new Dilithium private key
	_, privKey, err := mldsa87.GenerateKey(DilithiumReader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Dilithium private key: %v", err)
	}
	return &DilithiumRNG{
		privKey: privKey,
	}, nil
}

func GenerateKyberKeys() (*kyber768.PrivateKey, *kyber768.PublicKey, error) {
	kyberScheme := kyber768.Scheme()
	pubKey, privKey, err := kyberScheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Kyber keys: %v", err)
	}
	return privKey.(*kyber768.PrivateKey), pubKey.(*kyber768.PublicKey), nil
}

// Read fills the provided buffer with random bytes derived from a combination of the Dilithium private key and a counter.
func (d *DilithiumRNG) Read(p []byte) (n int, err error) {
	d.lock.Lock()
	defer d.lock.Unlock()

	if d.privKey == nil {
		return 0, fmt.Errorf("dilithium private key is nil")
	}

	bufferSize := len(p)
	output := make([]byte, 0, bufferSize)

	for len(output) < bufferSize {
		// Generate deterministic random bytes using the private key and a counter
		privKeyBytes, err := d.privKey.MarshalBinary()
		if err != nil {
			return 0, fmt.Errorf("failed to marshal private key: %v", err)
		}

		// Increment counter for uniqueness
		d.counter++
		counterBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(counterBytes, d.counter)

		combinedData := append(privKeyBytes, counterBytes...)
		hash := sha512.Sum512(combinedData)

		output = append(output, hash[:]...)
	}

	// Copy the required amount to the output buffer
	copy(p, output[:bufferSize])
	return bufferSize, nil
}

// DilithiumReader is a global instance of DilithiumRNG to replace cryptod.DilithiumReader.
var DilithiumReader io.Reader

func init() {
	var err error
	DilithiumReader, err = NewDilithiumRNG()
	if err != nil {
		panic("Failed to initialize Dilithium RNG: " + err.Error())
	}
}

// GenerateRandomNumber generates a random number using Dilithium keys.
func GenerateRandomNumber(privKey *mldsa87.PrivateKey, pubKey *mldsa87.PublicKey) (uint64, error) {
	privKeyBytes, err := privKey.MarshalBinary()
	if err != nil {
		return 0, fmt.Errorf("failed to marshal private key: %v", err)
	}
	pubKeyBytes, err := pubKey.MarshalBinary()
	if err != nil {
		return 0, fmt.Errorf("failed to marshal public key: %v", err)
	}

	// Include dynamic data (e.g., timestamp)
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().UnixNano()))

	combinedData := append(append(privKeyBytes, pubKeyBytes...), timestamp...)
	hash := sha512.Sum512(combinedData)
	randNum := new(big.Int).SetBytes(hash[:8]).Uint64()
	return randNum, nil
}

// GenerateSequentialNonce generates a sequential transaction-related nonce (uint64).
type SequentialNonceGenerator struct {
	counter uint64
	lock    sync.Mutex
}

// NewSequentialNonceGenerator initializes a new sequential nonce generator starting from a given value.
func NewSequentialNonceGenerator(start uint64) *SequentialNonceGenerator {
	return &SequentialNonceGenerator{counter: start}
}

// Next generates the next sequential nonce.
func (s *SequentialNonceGenerator) Next() uint64 {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.counter++
	return s.counter
}

// GenerateNonce generates a cryptographic nonce for GCM or other protocols.
func GenerateNonce(privKey *kyber768.PrivateKey, pubKey *kyber768.PublicKey, size int) ([]byte, error) {
	privKeyBytes, err := privKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	pubKeyBytes, err := pubKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	// Include dynamic data (e.g., timestamp)
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().UnixNano()))

	combinedData := append(append(privKeyBytes, pubKeyBytes...), timestamp...)
	hash := sha512.Sum512(combinedData)

	// Truncate or pad the hash to the desired nonce size
	if size > len(hash) {
		padded := make([]byte, size)
		copy(padded, hash[:])
		return padded, nil
	}
	return hash[:size], nil
}

// GCMNonceSize provides a standard nonce size for GCM.
func GCMNonceSize() int {
	return 12 // GCM standard nonce size is 12 bytes
}
