package sanitize

import (
	"github.com/sp301415/tfhe-go/math/csprng"
	"github.com/sp301415/tfhe-go/math/poly"
	"github.com/sp301415/tfhe-go/tfhe"
)

type Sanitizer struct {
	Parameters Parameters

	BaseEvaluator *tfhe.Evaluator[uint64]

	PublicKey tfhe.PublicKey[uint64]

	RandDGSampler  *ReverseCDTSampler
	MulDGSampler   [2]*ReverseCDTSampler
	RoundedSampler *csprng.GaussianSampler[uint64]

	r  poly.Poly[uint64]
	e1 poly.Poly[uint64]

	randGLWE tfhe.GLWECiphertext[uint64]
	randLWE  tfhe.LWECiphertext[uint64]

	ctKeySwitch tfhe.LWECiphertext[uint64]
	ctRotate    tfhe.GLWECiphertext[uint64]

	idLut tfhe.LookUpTable[uint64]

	pSplitBuff  poly.Poly[uint64]
	fpSplitBuff [5]poly.FourierPoly

	p0Split    [5]poly.FourierPoly
	p1Split    [5]poly.FourierPoly
	fpGaussian poly.FourierPoly
}

func NewSanitizer(params Parameters, pk tfhe.PublicKey[uint64], evk tfhe.EvaluationKey[uint64]) *Sanitizer {
	eval := tfhe.NewEvaluator(params.Parameters, evk)

	fpSplitBuff := [5]poly.FourierPoly{}
	p0Split := [5]poly.FourierPoly{}
	p1Split := [5]poly.FourierPoly{}
	for i := 0; i < 5; i++ {
		fpSplitBuff[i] = eval.PolyEvaluator.NewFourierPoly()
		p0Split[i] = eval.PolyEvaluator.NewFourierPoly()
		p1Split[i] = eval.PolyEvaluator.NewFourierPoly()
	}

	p := float64(params.MessageModulus() << 1)

	return &Sanitizer{
		Parameters: params,

		BaseEvaluator: eval,

		PublicKey: pk,

		RandDGSampler: NewReverseCDTSampler(0, params.SigRand),
		MulDGSampler: [2]*ReverseCDTSampler{
			NewReverseCDTSampler(0, params.SigMul/p),
			NewReverseCDTSampler(-1.0/p, params.SigMul/p),
		},
		RoundedSampler: csprng.NewGaussianSampler[uint64](),

		r:  poly.NewPoly[uint64](params.PolyDegree()),
		e1: poly.NewPoly[uint64](params.PolyDegree()),

		randGLWE: tfhe.NewGLWECiphertext(params.Parameters),
		randLWE:  tfhe.NewLWECiphertext(params.Parameters),

		ctKeySwitch: tfhe.NewLWECiphertextCustom[uint64](params.LWEDimension()),
		ctRotate:    tfhe.NewGLWECiphertext(params.Parameters),

		idLut: eval.GenLookUpTable(func(i int) int { return i }),

		pSplitBuff:  eval.PolyEvaluator.NewPoly(),
		fpSplitBuff: fpSplitBuff,

		p0Split:    p0Split,
		p1Split:    p1Split,
		fpGaussian: eval.PolyEvaluator.NewFourierPoly(),
	}
}

func (s *Sanitizer) RandAssign(ctOut tfhe.LWECiphertext[uint64]) {
	for i := 0; i < s.Parameters.PolyDegree(); i++ {
		s.r.Coeffs[i] = uint64(s.RandDGSampler.Sample())
		s.e1.Coeffs[i] = uint64(s.RandDGSampler.Sample())
	}
	s.BaseEvaluator.PolyEvaluator.ToFourierPolyAssign(s.r, s.fpGaussian)

	s.Split5(s.PublicKey.GLWEKey.Value[0].Value[1], s.p1Split)
	s.MulSplit5(s.fpGaussian, s.p1Split, s.randGLWE.Value[1])
	s.BaseEvaluator.PolyEvaluator.AddPolyAssign(s.e1, s.randGLWE.Value[1], s.randGLWE.Value[1])

	s.randGLWE.ToLWECiphertextAssign(0, ctOut)

	ctOut.Value[0] = s.r.Coeffs[0] * s.PublicKey.GLWEKey.Value[0].Value[0].Coeffs[0]
	for i := 1; i < s.Parameters.PolyDegree(); i++ {
		ctOut.Value[0] -= s.r.Coeffs[i] * s.PublicKey.GLWEKey.Value[0].Value[0].Coeffs[s.Parameters.PolyDegree()-i]
	}

	ctOut.Value[0] += s.RoundedSampler.Sample(s.Parameters.TauRand)
}

func (s *Sanitizer) SanitizeAssign(ct, ctOut tfhe.LWECiphertext[uint64]) {
	s.RandAssign(s.randLWE)
	s.BaseEvaluator.AddLWEAssign(ct, s.randLWE, s.randLWE)

	s.BaseEvaluator.KeySwitchForBootstrapAssign(s.randLWE, s.ctKeySwitch)

	b := s.BaseEvaluator.ModSwitch(s.ctKeySwitch.Value[0])
	s.ctKeySwitch.Value[0] = 0

	s.BaseEvaluator.BlindRotateAssign(s.ctKeySwitch, s.idLut, s.ctRotate)

	s.r.Coeffs[0] = 1 + (s.Parameters.MessageModulus()<<1)*uint64(s.MulDGSampler[1].Sample())
	for i := 1; i < s.Parameters.PolyDegree(); i++ {
		s.r.Coeffs[i] = (s.Parameters.MessageModulus() << 1) * uint64(s.MulDGSampler[0].Sample())
	}
	s.BaseEvaluator.PolyEvaluator.MonomialMulPolyInPlace(s.r, -b)
	s.BaseEvaluator.PolyEvaluator.ToFourierPolyAssign(s.r, s.fpGaussian)
	s.Split5(s.ctRotate.Value[1], s.p1Split)
	s.MulSplit5(s.fpGaussian, s.p1Split, s.ctRotate.Value[1])

	s.ctRotate.ToLWECiphertextAssign(0, ctOut)
	ctOut.Value[0] = s.r.Coeffs[0] * s.ctRotate.Value[0].Coeffs[0]
	for i := 1; i < s.Parameters.PolyDegree(); i++ {
		ctOut.Value[0] -= s.r.Coeffs[i] * s.ctRotate.Value[0].Coeffs[s.Parameters.PolyDegree()-i]
	}
	ctOut.Value[0] += s.RoundedSampler.Sample(s.Parameters.TauMul)

	s.RandAssign(s.randLWE)
	s.BaseEvaluator.AddLWEAssign(ctOut, s.randLWE, ctOut)
}
