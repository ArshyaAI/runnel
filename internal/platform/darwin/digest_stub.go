//go:build !darwin

package darwin

import "context"

func readFileDigestNoFollow(_ context.Context, _ string, _ int64) (fileDigestWitness, error) {
	return fileDigestWitness{}, ErrUnsupported
}
