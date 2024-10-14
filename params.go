package sanitize

import (
	"math"

	"github.com/sp301415/tfhe-go/tfhe"
)

const (
	GaussianBound      = 13.15
	SmoothingParameter = 6.0
)

type ParametersLiteral tfhe.ParametersLiteral[uint64]

type Parameters struct {
	tfhe.Parameters[uint64]

	SigRand float64
	TauRand float64
	SigMul  float64
	TauMul  float64
}

var (
	ParamsBinarySanitize11 = ParametersLiteral{
		LWEDimension: 612,
		GLWERank:     1,
		PolyDegree:   2048,

		BlockSize: 1,

		MessageModulus: 1 << 1,

		LWEStdDev:  0.00007905932600864546,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BootstrapParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 9,
			Level: 4,
		},
		KeySwitchParameters: tfhe.GadgetParametersLiteral[uint64]{
			Base:  1 << 3,
			Level: 4,
		},

		BootstrapOrder: tfhe.OrderKeySwitchBlindRotate,
	}
)

func (p ParametersLiteral) Compile() Parameters {
	params := tfhe.ParametersLiteral[uint64](p).Compile()

	sigRand, tauRand := RandParams(params)
	sigMul, tauMul := MulParams(params)

	return Parameters{
		Parameters: params,

		SigRand: sigRand,
		TauRand: tauRand,
		SigMul:  sigMul,
		TauMul:  tauMul,
	}
}

func KeySwitchVariance(params tfhe.Parameters[uint64]) float64 {
	q := math.Exp2(float64(params.LogQ()))
	N := float64(params.PolyDegree())
	Bks := float64(params.KeySwitchParameters().Base())
	Lks := float64(params.KeySwitchParameters().Level())
	sigLWE := params.LWEStdDevQ()

	v0 := (q * q * N) / (12 * math.Pow(Bks, 2*Lks))
	v1 := (sigLWE * sigLWE * Lks * N * Bks * Bks) / 12

	return v0 + v1
}

func ModSwitchVariance(params tfhe.Parameters[uint64]) float64 {
	n := float64(params.LWEDimension())
	return ((n + 1) / 12) * math.Exp2(float64(2*(params.LogQ()-params.PolyDegreeLog()-1)))
}

func BlindRotateVariance(params tfhe.Parameters[uint64]) float64 {
	q := math.Exp2(float64(params.LogQ()))
	n := float64(params.LWEDimension())
	N := float64(params.PolyDegree())
	Bbr := float64(params.BootstrapParameters().Base())
	Lbr := float64(params.BootstrapParameters().Level())
	sigGLWE := params.GLWEStdDevQ()

	v0 := (n * (N + 1) * q * q) / (12 * math.Pow(Bbr, 2*Lbr))
	v1 := (n * Lbr * N * sigGLWE * sigGLWE * Bbr * Bbr) / 6

	return v0 + v1
}

func RandParams(params tfhe.Parameters[uint64]) (sig, tau float64) {
	N := float64(params.PolyDegree())
	sigGLWE := params.GLWEStdDevQ()
	B := GaussianBound * sigGLWE

	S := N * N * (1 + B*B)
	T := N * (sigGLWE*sigGLWE + 1.0/4.0)

	sig = SmoothingParameter * math.Sqrt((math.Sqrt(S)+math.Sqrt(T))/math.Sqrt(T))
	tau = sig * math.Sqrt(math.Sqrt(S*T))

	return
}

func RandVariance(params tfhe.Parameters[uint64]) float64 {
	N := float64(params.PolyDegree())
	sigGLWE := params.GLWEStdDevQ()

	sig, tau := RandParams(params)
	return N*(sigGLWE*sigGLWE+1.0/4.0)*sig*sig + tau*tau + 1.0/12.0
}

func MulParams(params tfhe.Parameters[uint64]) (sig, tau float64) {
	N := float64(params.PolyDegree())
	varBR := BlindRotateVariance(params)
	sigBR := math.Sqrt(varBR)
	B := GaussianBound * sigBR
	p := float64(params.MessageModulus() << 1)

	S := N * N * B * B
	T := N * varBR

	sig = p * SmoothingParameter * math.Sqrt((math.Sqrt(S)+math.Sqrt(T))/math.Sqrt(T))
	tau = sig * math.Sqrt(math.Sqrt(S*T))

	return
}

func MulVariance(params tfhe.Parameters[uint64], varIn float64) float64 {
	N := float64(params.PolyDegree())

	sig, tau := MulParams(params)

	return N*varIn*sig*sig + tau*tau + 1.0/12.0 + RandVariance(params)
}

func BootstrapVariance(params tfhe.Parameters[uint64]) float64 {
	return BlindRotateVariance(params) + KeySwitchVariance(params) + ModSwitchVariance(params) + RandVariance(params)
}
