package photoproof

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/drakstik/Photognark_V3/src/image"
)

// Proof that is used outside the circuit
type Proof struct {
	PCD_Proof groth16.Proof
	Signature []byte
}

func (user User) Prove(prover ProverKeys, z_in image.Z, tr Transformation, params Transformation_Parameters, proof_in Proof) (image.Z, Proof, error) {
	// Case 1: Only a signature, no PCD_Proof
	if proof_in.PCD_Proof == nil {

		/* Algorithm 3, 3: {"convert” the signature to PCD proof by calling the PCD prover}*/
		fr_z_in := z_in.ToFr()

		// Assign the input signature to its eddsa equivilant
		var eddsa_digSig eddsa.Signature
		eddsa_digSig.Assign(1, proof_in.Signature)

		circuit := Permissible_Transformations{
			Output:    fr_z_in,
			Signature: eddsa_digSig,
			Case_1:    frontend.Variable(1),
		}

		// Create the secret witness from the circuit (runs Define())
		secret_witness_out, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
		if err != nil {
			return image.Z{}, Proof{}, err
		}

		// Set the security parameter and compile a constraint system (aka compliance_predicate) (runs Define())
		compliance_predicate, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		if err != nil {
			return image.Z{}, Proof{}, err
		}

		// Create pcd_proof_out that the secret witness adheres to the compliance predicate, using the given proving key (runs Define())
		pcd_proof_out, err := groth16.Prove(compliance_predicate, prover.ProvingKey, secret_witness_out)
		if err != nil {
			return image.Z{}, Proof{}, err
		}

		return z_in, Proof{
			PCD_Proof: pcd_proof_out,
			Signature: proof_in.Signature,
		}, err
	} else {
		/* From paper: Algorithm 3, 5-9: "π'in ← πin" */
		img_out := tr.Apply(z_in.Img, &params) // Algorithm 3, 6: "Iout ← t (Iin, γ)"

		// Sign output image
		signature_out, err := user.Sign(img_out)
		if err != nil {
			fmt.Println("[Prove()] Error while Signing the output image.")
			return image.Z{}, Proof{}, err
		}

		// Assign signature to its EdDSA equivalent.
		var eddsa_digSig eddsa.Signature
		eddsa_digSig.Assign(1, signature_out)

		// Assign public key to its EdDSA equivalent.
		var eddsa_PK eddsa.PublicKey
		eddsa_PK.Assign(1, user.PublicKey.Bytes())

		// Set Public Key of fr_z_in
		fr_z_in := z_in.ToFr()
		fr_z_in.PublicKey = eddsa_PK

		circuit := Permissible_Transformations{} // Instantiate new circuit

		// Depending on the tr.GetName(), Set the appropriate flag in the circuit's list of fr_transformations.
		switch tr.GetName() {
		case "Identity":
			circuit = Permissible_Transformations{
				Input: fr_z_in,
				Output: image.Fr_Z{
					Img:       img_out.ToFr(),
					PublicKey: eddsa_PK,
				},
				Signature:  eddsa_digSig,
				Parameters: params.ToFr(),
				Identity: Fr_Identity_Transformation{
					Flag: frontend.Variable(1),
				},
				Case_1: frontend.Variable(0), // Not case 1; Not original image
			}
		}

		// Create the secret witness from the circuit
		secret_witness_out, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
		if err != nil {
			return image.Z{}, Proof{}, err
		}

		// Set the security parameter and compile a constraint system (aka compliance_predicate)
		compliance_predicate, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		if err != nil {
			return image.Z{}, Proof{}, err
		}

		// Create proof_out that the secret witness adheres to the compliance predicate, using the given proving key
		proof_out, err := groth16.Prove(compliance_predicate, prover.ProvingKey, secret_witness_out)
		if err != nil {
			return image.Z{}, Proof{}, err
		}

		// Replace image in z_in to create z_out
		z_in.Img = img_out
		z_out := z_in

		return z_out, Proof{
			PCD_Proof: proof_out,
			Signature: proof_in.Signature,
		}, err
	}
}
