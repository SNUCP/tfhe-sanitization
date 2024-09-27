package sanitize

import (
	"testing"

	"github.com/sp301415/tfhe-go/tfhe"
)

var (
	enc = tfhe.NewEncryptor(ParamsBinarySanitize.Parameters)
	san = NewSanitizer(ParamsBinarySanitize, enc.GenPublicKey(), enc.GenEvaluationKeyParallel())
)

func TestSanitize(t *testing.T) {
	for m := range []int{0, 1} {
		ct := enc.EncryptLWE(m)
		ctOut := tfhe.NewLWECiphertext(ParamsBinarySanitize.Parameters)
		san.SanitizeAssign(ct, ctOut)

		if enc.DecryptLWE(ctOut) != m {
			t.Fatalf("Sanitization failed: %d != %d", enc.DecryptLWE(ctOut), m)
		}
	}
}

func BenchmarkBootstrap(b *testing.B) {
	ct := enc.EncryptLWE(0)
	idLUT := san.BaseEvaluator.GenLookUpTable(func(i int) int { return i })
	for i := 0; i < b.N; i++ {
		san.BaseEvaluator.BootstrapLUTAssign(ct, idLUT, ct)
	}
}

func BenchmarkSanitize(b *testing.B) {
	ct := enc.EncryptLWE(0)
	for i := 0; i < b.N; i++ {
		san.SanitizeAssign(ct, ct)
	}
}
