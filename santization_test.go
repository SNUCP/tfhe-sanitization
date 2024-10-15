package sanitize

import (
	"math"
	"testing"

	"github.com/sp301415/tfhe-go/tfhe"
)

var (
	params = ParamsBinarySanitize11.Compile()
	enc    = tfhe.NewEncryptor(params.Parameters)
	san    = NewSanitizer(params, enc.GenPublicKey(), enc.GenEvaluationKeyParallel())
)

func TestSanitize(t *testing.T) {
	for m := range []int{0, 1} {
		ct := enc.EncryptLWE(m)
		ctOut := tfhe.NewLWECiphertext(params.Parameters)
		san.SanitizeAssign(ct, ctOut)

		if enc.DecryptLWE(ctOut) != m {
			t.Fatalf("Sanitization failed: %d != %d", enc.DecryptLWE(ctOut), m)
		}
	}
}

func BenchmarkBootstrap(b *testing.B) {
	ct := enc.EncryptLWE(0)
	idLUT := san.BaseEvaluator.GenLookUpTable(func(i int) int { return i })

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		san.BaseEvaluator.BootstrapLUTAssign(ct, idLUT, ct)
	}
}

func BenchmarkSanitize(b *testing.B) {
	ct := enc.EncryptLWE(0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		san.SanitizeAssign(ct, ct)
	}
}

func BenchmarkSoakSpin(b *testing.B) {
	ct := enc.EncryptLWE(0)
	ctRand := enc.EncryptLWE(0)
	idLUT := san.BaseEvaluator.GenLookUpTable(func(i int) int { return i })

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 7; j++ {
			san.BaseEvaluator.BootstrapLUTAssign(ct, idLUT, ct)
			ct.Value[0] += san.RoundedSampler.Sample(math.Exp2(58.15))
		}
		san.RandAssign(ctRand)
		san.BaseEvaluator.AddLWEAssign(ctRand, ct, ct)
	}
}
