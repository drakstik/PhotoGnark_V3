package photoproof

import "github.com/consensys/gnark/frontend"

func Check_Transformation(api frontend.API, permissible Permissible_Transformations) frontend.Variable {
	/* Ensure that input public key and output public key are the same. */
	api.AssertIsEqual(permissible.Input.PublicKey.A.X, permissible.Output.PublicKey.A.X)
	api.AssertIsEqual(permissible.Input.PublicKey.A.Y, permissible.Output.PublicKey.A.Y)

	// Section V-F:
	// 		- the original hash either matches the image or
	// 		- th original hash is passed from input to output without modification
	api.AssertIsEqual(permissible.Input.OriginalHash, permissible.Output.OriginalHash)

	// Verify the output signature is valid.
	digest, mimc := permissible.Output.Img.Hash(api)
	Verify_Signature(api, digest, permissible.Signature, permissible.Output.PublicKey, mimc)

	// TODO: ensure that all permissible transformations are applied
	/* Run Identity Transformation check if flag is on. */
	api.Select(
		permissible.Identity.Flag,
		permissible.Identity.Apply(api, permissible.Input, permissible.Output, permissible.Parameters, permissible.Signature),
		frontend.Variable(0),
	)

	return 1
}
