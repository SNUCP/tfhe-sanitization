package sanitize

import (
	"math"

	"github.com/sp301415/tfhe-go/tfhe"
)

const (
	GaussianBound      = 6.0
	SmoothingParameter = 6.0
)

type Parameters struct {
	tfhe.Parameters[uint64]

	BlindRotateBound float64
}

var (
	ParamsBinarySanitize = Parameters{
		Parameters: tfhe.ParametersLiteral[uint64]{
			LWEDimension: 687,
			GLWERank:     1,
			PolyDegree:   2048,

			BlockSize: 3,

			MessageModulus: 1 << 1,

			LWEStdDev:  0.000020524870466164442,
			GLWEStdDev: 0.0000000000000003472576015484159,

			BootstrapParameters: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 15,
				Level: 2,
			},
			KeySwitchParameters: tfhe.GadgetParametersLiteral[uint64]{
				Base:  1 << 4,
				Level: 3,
			},

			BootstrapOrder: tfhe.OrderKeySwitchBlindRotate,
		}.Compile(),

		BlindRotateBound: math.Exp2(39.083427976403456),
	}
)

func (p Parameters) RandSigma() float64 {
	sig := p.GLWEStdDevQ()
	N := float64(p.PolyDegree())
	return sig * math.Sqrt(2*math.Sqrt(N)+2)
}

func (p Parameters) RandTau() float64 {
	sig := p.GLWEStdDevQ()
	K := GaussianBound
	N := float64(p.PolyDegree())
	return sig * math.Sqrt(2*(N+math.Sqrt(N))*(1+K*K*sig*sig)) / math.Sqrt(2*math.Pi)
}

func (p Parameters) MulSigma() float64 {
	eta := SmoothingParameter
	N := float64(p.PolyDegree())
	t := float64(p.MessageModulus() << 1)

	return t * eta * math.Sqrt(math.Sqrt(N)+1)
}

func (p Parameters) MulTau() float64 {
	eta := SmoothingParameter
	N := float64(p.PolyDegree())
	t := float64(p.MessageModulus() << 1)
	B := p.BlindRotateBound

	return B * t * eta * math.Sqrt(N*N+N*math.Sqrt(N)) / math.Sqrt(2*math.Pi)
}
