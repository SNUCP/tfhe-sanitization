package sanitize

import (
	"math"
	"slices"

	"github.com/sp301415/tfhe-go/math/csprng"
)

const TailCut = 13

// ReverseCDTSampler is a Discrete Gaussian sampler based on Reverse Cumulative Distribution Table.
// Recommended for fixed and small center and sigma.
//
// Note that the stdandard devation of the samples is sigma/sqrt(2pi).
type ReverseCDTSampler struct {
	// UniformSampler is a base uniform sampler.
	UniformSampler *csprng.UniformSampler[uint64]

	// Table is a table of probabilities.
	Table []uint64

	// Center is the center of the distribution.
	Center float64
	// Sigma is the standard deviation of the distribution.
	Sigma float64

	// TailLow is the lower bound of the tail.
	// Currently, tail cut of 6 sigma is used.
	TailLow int64
	// TailHigh is the upper bound of the tail.
	// Currently, tail cut of 6 sigma is used.
	TailHigh int64

	// cInt is the integer part of the center.
	cInt int64
	// cFrac is the fractional part of the center.
	cFrac float64
}

// NewReverseCDTSampler creates a new ReverseCDTSampler.
func NewReverseCDTSampler(center, sigma float64) *ReverseCDTSampler {
	normFactor := math.Exp2(64)
	cFrac := center - math.Floor(center)
	cInt := int64(center - cFrac)

	tailLow := int64(math.Round(center - TailCut*sigma))
	tailHigh := int64(math.Round(center + TailCut*sigma))
	tailCount := int(tailHigh - tailLow + 1)

	table := make([]uint64, tailCount)
	cdf := 0.0
	for i, x := 0, tailLow; x <= tailHigh; i, x = i+1, x+1 {
		xf := float64(x)
		rho := math.Exp(-(xf-cFrac)*(xf-cFrac)/(2*sigma*sigma)) / (math.Sqrt(2*math.Pi) * sigma)
		cdf += rho
		if cdf > 1 {
			table[i] = math.MaxUint64
		} else {
			table[i] = uint64(math.Round(cdf * normFactor))
		}
	}

	return &ReverseCDTSampler{
		UniformSampler: csprng.NewUniformSampler[uint64](),

		Table: table,

		Center: center,
		Sigma:  sigma,

		TailLow:  tailLow,
		TailHigh: tailHigh,

		cInt:  cInt,
		cFrac: cFrac,
	}
}

// Sample samples one value from the distribution.
func (s *ReverseCDTSampler) Sample() int64 {
	u := s.UniformSampler.Sample()
	r, ok := slices.BinarySearch(s.Table, u)
	if ok {
		r -= 1
	}
	return int64(r) + s.cInt + s.TailLow
}
