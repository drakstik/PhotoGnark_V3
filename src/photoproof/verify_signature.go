package photoproof

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/drakstik/Photognark_V3/src/image"
)

func Verify_Original_Signature(api frontend.API, z image.Fr_Z) frontend.Variable {

	// Hash the fr_image
	digest, mimc := z.Img.Hash(api)

	// Section V-F: the original hash either matches the image or ...
	// Check if image's hash is original image hash
	api.AssertIsEqual(z.OriginalHash, digest)

	// Verify the image against the original signature)
	Verify_Signature(api, digest, z.OriginalSignature, z.PublicKey, mimc)

	return 1
}

// Verify z.img, as a digest, against the dig_sig and z.PublicKey
func Verify_Signature(api frontend.API, digest frontend.Variable, dig_sig eddsa.Signature, public_key eddsa.PublicKey, mimc mimc.MiMC) frontend.Variable {

	// Hash the fr_image
	// digest, mimc := z.Img.Hash(api)

	// Set the twisted edwards curve to use
	curve, _ := twistededwards.NewEdCurve(api, tedwards.BN254)

	// verify the digest against the signature, using the public key
	eddsa.Verify(curve, dig_sig, digest, public_key, &mimc)

	return 1
}
