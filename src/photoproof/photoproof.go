package photoproof

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/drakstik/Photognark_V3/src/image"
)

/* Main circuit */
type Permissible_Transformations struct {
	Input  image.Fr_Z `gnark:",secret"`
	Output image.Fr_Z `gnark:",public"`

	Signature  eddsa.Signature              `gnark:",public"` // Either the original signature, or the output signature after a transformation
	Parameters Fr_Transformation_Parameters `gnark:",secret"`

	// TODO: use an array of Fr_Transformations instead of a specific transformation
	Identity Fr_Identity_Transformation `gnark:",secret"`

	Case_1 frontend.Variable `gnark:",secret"` // 1 if there is NO Input. Otherwise 0.
}

func (circuit Permissible_Transformations) Define(api frontend.API) error {
	/*
		Case 1: Verify the Output.Img against the signature, using the output's public key
		Case 2:
				a) Check that transformation from Input to Output is permissible
				b) Check that Input public key == Output public key
	*/
	ok := api.Select(
		circuit.Case_1,
		Verify_Original_Signature(api, circuit.Output),
		Check_Transformation(api, circuit),
	)

	// Assert that VerifySignature or CheckTransformation return 1
	api.AssertIsEqual(ok, 1)

	return nil
}
