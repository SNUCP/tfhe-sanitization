package sanitize

import "github.com/sp301415/tfhe-go/math/poly"

func (s *Sanitizer) Split5(p poly.Poly[uint64], fpSplit [5]poly.FourierPoly) {
	splitCount := 5
	splitBits := 13
	splitMask := uint64((1 << splitBits) - 1)

	for i := 0; i < splitCount; i++ {
		splitLowBits := i * splitBits
		for j := 0; j < p.Degree(); j++ {
			s.pSplitBuff.Coeffs[j] = (p.Coeffs[j] >> splitLowBits) & splitMask
		}
		s.BaseEvaluator.PolyEvaluator.ToFourierPolyAssign(s.pSplitBuff, fpSplit[i])
	}
}

func (s *Sanitizer) MulSplit5(fp poly.FourierPoly, fpSplit [5]poly.FourierPoly, pOut poly.Poly[uint64]) {
	splitCount := 5
	splitBits := 13

	for i := 0; i < splitCount; i++ {
		s.BaseEvaluator.PolyEvaluator.MulFourierPolyAssign(fp, fpSplit[i], s.fpSplitBuff[i])
	}

	s.BaseEvaluator.PolyEvaluator.ToPolyAssign(s.fpSplitBuff[0], pOut)
	for i := 1; i < splitCount; i++ {
		s.BaseEvaluator.PolyEvaluator.ToPolyAssignUnsafe(s.fpSplitBuff[i], s.pSplitBuff)
		splitLowBits := i * splitBits
		for j := 0; j < pOut.Degree(); j++ {
			pOut.Coeffs[j] += s.pSplitBuff.Coeffs[j] << splitLowBits
		}
	}
}
