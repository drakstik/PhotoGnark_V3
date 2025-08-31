package photoproof

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/drakstik/Photognark_V3/src/image"
)

// TODO: Create Fr_Identity_Transformation struct which implements Fr_Transformation
//			and Fr_Identity_Tr_Params struct which implements Fr_Transformation_Parameters

type Fr_Transformation_Parameters interface {
	GetName() frontend.Variable
}

type Fr_Transformation interface {
	GetName() frontend.Variable
	GetFlag() frontend.Variable // Either 0 or 1
	// TODO: When implementing Apply, Check relations between img_in and img_out, relevant for params, and assert they adhere
	// to ParamsBounds and ProvenanceBounds originally set by the admin.
	Apply(api frontend.API, img_in image.Fr_Z, img_out image.Fr_Z, params Fr_Transformation_Parameters, dig_sig eddsa.Signature) frontend.Variable
}

type Fr_Identity_Tr_Params struct {
	// TODO: This boolean can be used to run an
	// 		 in-circuit signature verification on the Original Signature
	// Originality_Decider frontend.Variable
}

func (params Fr_Identity_Tr_Params) GetName() frontend.Variable {
	return frontend.Variable([]byte("identity"))
}

type Fr_Identity_Transformation struct {
	Flag frontend.Variable
}

func (tr Fr_Identity_Transformation) GetName() frontend.Variable {
	return frontend.Variable([]byte("identity"))
}

// Either 0 or 1
func (tr Fr_Identity_Transformation) GetFlag() frontend.Variable {
	return tr.Flag
}

// Check that img_in & img_out are equivelant.
// return 0 if unsuccessful, 1 if successful
func (id_tr Fr_Identity_Transformation) Apply(api frontend.API, img_in image.Fr_Z, img_out image.Fr_Z, params Fr_Transformation_Parameters, dig_sig eddsa.Signature) frontend.Variable {
	digest_in, mimc := img_in.Img.Hash(api)   // The hash of the input image
	digest_out, mimc := img_out.Img.Hash(api) // The hash of the output image

	// Check if both hashes match against the same signature
	ok1 := Verify_Signature(api, digest_in, dig_sig, img_in.PublicKey, mimc)
	ok2 := Verify_Signature(api, digest_out, dig_sig, img_out.PublicKey, mimc)

	// Assert that both input & output images successfully verified against the same signature
	api.AssertIsEqual(1, ok1)
	api.AssertIsEqual(1, ok2)

	return 1
}
