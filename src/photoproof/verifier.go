package photoproof

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/drakstik/Photognark_V3/src/image"
)

// TODO:
// With modifications from Section V-F: The PhotoProof verifier checks that
//
//	(a) the PCD Proof is valid for the image with its attached original hash, and
//	(b) the signature of the original hash is valid under the signature scheme's public key.
func (user User) Verify(verifier_keys VerifierKeys, z_in image.Z, proof_in Proof) (bool, error) {

	hFunc := hash.NewHash("MIMC_BN254")

	// (b) the signature of the original hash is valid under the signature scheme's public key.
	verifier_keys.Original_PublicKey.Verify(z_in.OriginalSignature, z_in.OriginalHash, hFunc)

	// If the proof does NOT have a PCD_Proof, i.e. it's just a signature, then it's an original iamge
	if proof_in.PCD_Proof == nil {

		// Then verify the signature with the image, using the original public key.
		hFunc = hash.NewHash("MIMC_BN254")

		verifier_keys.Original_PublicKey.Verify(proof_in.Signature, z_in.Img.Hash(), hFunc)

	} else { // Else PCD_Proof exists, image has had at least identity transformation

		// Assign the input signature to its eddsa equivilant
		var eddsa_digSig eddsa.Signature
		eddsa_digSig.Assign(1, proof_in.Signature)

		/* (a) the PCD Proof is valid for the image with its attached original hash */

		// Recreate the constraint system with public values for identity transformation
		circuit := Permissible_Transformations{
			Output:    z_in.ToFr(),  // Public values
			Signature: eddsa_digSig, // Public values
		}

		// Recreate a secret witness
		secret_witness, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
		if err != nil {
			fmt.Println("ERROR: frontend.NewWitness() while verifying proof...\n" + err.Error())
			return false, err
		}

		// Recreate the public witness
		public_witness, err := secret_witness.Public()
		if err != nil {
			fmt.Println("ERROR: secret_witness.Public() while verifying proof..")
			return false, err
		}

		// Verify the proof with the recreated public witness and verifying key
		err = groth16.Verify(proof_in.PCD_Proof, verifier_keys.VerifyingKey, public_witness)
		if err != nil {
			fmt.Println("ERROR: VerifyGnarkProof failed.")
			return false, err
		}
	}

	return true, nil

}
