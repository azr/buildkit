package contenthash

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/zeebo/blake3"
)

// algorithmContextKey is the context key for storing the checksum algorithm.
// Using a string key allows other packages to access it without importing this package.
const algorithmContextKey = "buildkit.contenthash.algorithm"

var (
	// defaultAlgorithm is the default checksum algorithm
	// Set once at daemon startup, then only read (no lock needed)
	defaultAlgorithm = digest.SHA256
)

// blake3HashImpl implements digest.CryptoHash for BLAKE3
type blake3HashImpl struct{}

func (blake3HashImpl) Available() bool {
	return true
}

func (blake3HashImpl) Size() int {
	return blake3.New().Size()
}

func (blake3HashImpl) New() hash.Hash {
	return blake3.New()
}

func init() {
	// Register SHA384 algorithm (not registered by default in go-digest)
	digest.RegisterAlgorithm(digest.SHA384, crypto.SHA384)

	// Register BLAKE3 algorithm
	blake3Impl := &blake3HashImpl{}
	digest.RegisterAlgorithm(digest.BLAKE3, blake3Impl)
}

// SetAlgorithm sets the default checksum algorithm for content hashing.
// Supported algorithms: "sha256", "sha384", "sha512", "blake3"
// Should only be called at daemon startup, before any concurrent reads.
func SetAlgorithm(alg string) error {
	switch alg {
	case "sha256":
		defaultAlgorithm = digest.SHA256
	case "sha384":
		defaultAlgorithm = digest.SHA384
	case "sha512":
		defaultAlgorithm = digest.SHA512
	case "blake3":
		defaultAlgorithm = digest.BLAKE3
	default:
		return errors.Errorf("unsupported checksum algorithm: %s (supported: sha256, sha384, sha512, blake3)", alg)
	}
	return nil
}

// GetAlgorithm returns the current default checksum algorithm
func GetAlgorithm() digest.Algorithm {
	return defaultAlgorithm
}

// GetAlgorithmFromContext returns the checksum algorithm from context, or the default if not set
func GetAlgorithmFromContext(ctx context.Context) digest.Algorithm {
	if ctx != nil {
		if alg, ok := ctx.Value(algorithmContextKey).(digest.Algorithm); ok && alg != "" {
			return alg
		}
	}
	return GetAlgorithm()
}

// WithAlgorithm returns a context with the checksum algorithm set
func WithAlgorithm(ctx context.Context, alg string) (context.Context, error) {
	var dgstAlg digest.Algorithm
	switch alg {
	case "sha256":
		dgstAlg = digest.SHA256
	case "sha384":
		dgstAlg = digest.SHA384
	case "sha512":
		dgstAlg = digest.SHA512
	case "blake3":
		dgstAlg = digest.BLAKE3
	default:
		return nil, errors.Errorf("unsupported checksum algorithm: %s (supported: sha256, sha384, sha512, blake3)", alg)
	}
	return context.WithValue(ctx, algorithmContextKey, dgstAlg), nil
}

// NewHash creates a new hash.Hash instance for the configured algorithm
func NewHash() (hash.Hash, error) {
	return NewHashFromContext(context.Background())
}

// NewHashFromContext creates a new hash.Hash instance using the algorithm from context (or default)
func NewHashFromContext(ctx context.Context) (hash.Hash, error) {
	alg := GetAlgorithmFromContext(ctx)
	return newHashForAlgorithm(alg)
}

// newHashForAlgorithm creates a new hash.Hash instance for the specified algorithm
func newHashForAlgorithm(alg digest.Algorithm) (hash.Hash, error) {
	switch alg {
	case digest.SHA256:
		return sha256.New(), nil
	case digest.SHA384:
		return sha512.New384(), nil
	case digest.SHA512:
		return sha512.New(), nil
	case digest.BLAKE3:
		// Use go-digest's BLAKE3 support
		return digest.BLAKE3.Hash(), nil
	default:
		// Try to use the algorithm if it's available in go-digest
		if alg.Available() {
			return alg.Hash(), nil
		}
		return nil, errors.Errorf("unsupported checksum algorithm: %s", alg)
	}
}

// NewDigest creates a digest from a hash.Hash using the configured algorithm
func NewDigest(h hash.Hash) (digest.Digest, error) {
	return NewDigestFromContext(context.Background(), h)
}

// NewDigestFromContext creates a digest from a hash.Hash using the algorithm from context (or default)
func NewDigestFromContext(ctx context.Context, h hash.Hash) (digest.Digest, error) {
	alg := GetAlgorithmFromContext(ctx)
	return digest.NewDigest(alg, h), nil
}
