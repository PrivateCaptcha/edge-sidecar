package common

import randv2 "math/rand/v2"

type TFingerprint = uint64

func RandomFingerprint() TFingerprint {
	return randv2.Uint64()
}
