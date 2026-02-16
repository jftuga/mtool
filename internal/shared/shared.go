package shared

import (
	"fmt"
	"io"
	"math/big"
	"os"

	crand "crypto/rand"
)

// FormatSize formats a byte count into a human-readable string.
func FormatSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ReadInput reads from the first file in args, or from stdin if args is empty.
func ReadInput(args []string) ([]byte, error) {
	if len(args) > 0 {
		return os.ReadFile(args[0])
	}
	return io.ReadAll(os.Stdin)
}

// CryptoRandIntn returns a cryptographically secure random int in [0, n).
func CryptoRandIntn(n int) (int, error) {
	max := big.NewInt(int64(n))
	val, err := crand.Int(crand.Reader, max)
	if err != nil {
		return 0, err
	}
	return int(val.Int64()), nil
}
