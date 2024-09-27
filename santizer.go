package sanitize

import (
	"github.com/sp301415/dgs"
	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

type Sanitizer struct {
	Parameters Parameters

	BaseEvaluator *tfhe.Evaluator[uint64]

	PublicKey tfhe.PublicKey[uint64]

	RandSigmaSampler *dgs.ReverseCDTSampler
	MulSigmaSamplers [2]*dgs.ReverseCDTSampler
	RoundedSampler   *csprng.GaussianSampler[uint64]

	r  poly.Poly[uint64]
	e1 poly.Poly[uint64]

	randGLWE tfhe.GLWECiphertext[uint64]
	randLWE  tfhe.LWECiphertext[uint64]

	ctKeySwitch tfhe.LWECiphertext[uint64]
	ctRotate    tfhe.GLWECiphertext[uint64]

	idLut tfhe.LookUpTable[uint64]
}

func NewSanitizer(params Parameters, pk tfhe.PublicKey[uint64], evk tfhe.EvaluationKey[uint64]) *Sanitizer {
	eval := tfhe.NewEvaluator(params.Parameters, evk)

	return &Sanitizer{
		Parameters: params,

		BaseEvaluator: eval,

		PublicKey: pk,

		RandSigmaSampler: dgs.NewReverseCDTSampler(0, params.RandSigma()),
		MulSigmaSamplers: [2]*dgs.ReverseCDTSampler{
			dgs.NewReverseCDTSampler(0, params.MulSigma()),
			dgs.NewReverseCDTSampler(-1.0/float64(params.MessageModulus()<<1), params.MulSigma()),
		},
		RoundedSampler: csprng.NewGaussianSampler[uint64](),

		r:  poly.NewPoly[uint64](params.PolyDegree()),
		e1: poly.NewPoly[uint64](params.PolyDegree()),

		randGLWE: tfhe.NewGLWECiphertext(params.Parameters),
		randLWE:  tfhe.NewLWECiphertext(params.Parameters),

		ctKeySwitch: tfhe.NewLWECiphertextCustom[uint64](params.LWEDimension()),
		ctRotate:    tfhe.NewGLWECiphertext(params.Parameters),

		idLut: eval.GenLookUpTable(func(i int) int { return i }),
	}
}

func (s *Sanitizer) RandAssign(ctOut tfhe.LWECiphertext[uint64]) {
	for i := 0; i < s.Parameters.PolyDegree(); i++ {
		s.r.Coeffs[i] = uint64(s.RandSigmaSampler.Sample())
		s.e1.Coeffs[i] = uint64(s.RandSigmaSampler.Sample())
	}

	pev := s.BaseEvaluator.PolyEvaluator
	pev.MulPolyAssign(s.r, s.PublicKey.GLWEKey.Value[0].Value[0], s.randGLWE.Value[0])
	pev.MulPolyAssign(s.r, s.PublicKey.GLWEKey.Value[0].Value[1], s.randGLWE.Value[1])
	pev.AddPolyAssign(s.e1, s.randGLWE.Value[1], s.randGLWE.Value[1])

	s.randGLWE.ToLWECiphertextAssign(0, ctOut)
	ctOut.Value[0] += s.RoundedSampler.Sample(s.Parameters.RandTau())
}

func (s *Sanitizer) SanitizeAssign(ct, ctOut tfhe.LWECiphertext[uint64]) {
	s.RandAssign(s.randLWE)
	s.BaseEvaluator.AddLWEAssign(ct, s.randLWE, s.randLWE)

	s.BaseEvaluator.KeySwitchForBootstrapAssign(s.randLWE, s.ctKeySwitch)

	b := s.BaseEvaluator.ModSwitch(s.ctKeySwitch.Value[0])
	s.ctKeySwitch.Value[0] = 0

	s.BaseEvaluator.BlindRotateAssign(s.ctKeySwitch, s.idLut, s.ctRotate)

	s.r.Coeffs[0] = 1 + (s.Parameters.MessageModulus()<<1)*uint64(s.MulSigmaSamplers[1].Sample())
	for i := 1; i < s.Parameters.PolyDegree(); i++ {
		s.r.Coeffs[i] = (s.Parameters.MessageModulus() << 1) * uint64(s.MulSigmaSamplers[0].Sample())
	}
	s.BaseEvaluator.PolyEvaluator.MonomialMulPolyInPlace(s.r, -b)
	s.BaseEvaluator.PolyEvaluator.MulPolyAssign(s.ctRotate.Value[0], s.r, s.ctRotate.Value[0])
	s.BaseEvaluator.PolyEvaluator.MulPolyAssign(s.ctRotate.Value[1], s.r, s.ctRotate.Value[1])

	s.ctRotate.ToLWECiphertextAssign(0, ctOut)
	ctOut.Value[0] += s.RoundedSampler.Sample(s.Parameters.MulTau())

	s.RandAssign(s.randLWE)
	s.BaseEvaluator.AddLWEAssign(ctOut, s.randLWE, ctOut)
}
