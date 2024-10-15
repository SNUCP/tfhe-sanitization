package sanitize

import "github.com/sp301415/tfhe-go/math/poly"

func (s *Sanitizer) Split3(p poly.Poly[uint64], fpSplit [3]poly.FourierPoly) {
	splitCount := 3
	splitBits := 22
	splitMask := uint64((1 << splitBits) - 1)

	for i := 0; i < splitCount; i++ {
		splitLowBits := i * splitBits
		for j := 0; j < p.Degree(); j++ {
			s.pSplitBuff.Coeffs[j] = (p.Coeffs[j] >> splitLowBits) & splitMask
		}
		s.BaseEvaluator.PolyEvaluator.ToFourierPolyAssign(s.pSplitBuff, fpSplit[i])
	}
}

func (s *Sanitizer) MulSplit3(fp poly.FourierPoly, fpSplit [3]poly.FourierPoly, pOut poly.Poly[uint64]) {
	splitCount := 3
	splitBits := 22

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
