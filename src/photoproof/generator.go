package photoproof

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

type ProverKeys struct {
	ProvingKey         groth16.ProvingKey
	Original_PublicKey signature.PublicKey
}

type VerifierKeys struct {
	VerifyingKey       groth16.VerifyingKey
	Original_PublicKey signature.PublicKey
}

func Generator(circuit *Permissible_Transformations) (ProverKeys, VerifierKeys, User) {
	// 1. Generate a secret & public key using ceddsa.
	// secret_key, err := ceddsa.New(1, rand.Reader) // Generate a secret key for signing
	// if err != nil {
	// 	fmt.Println("func NewSecretKey(): Error while generating secret key using ceddsa...")
	// 	fmt.Print(err.Error())
	// 	return Prover{}, Verifier{}, nil
	// }

	// public_key := secret_key.Public()

	user := NewUser()

	// Set the security parameter (BN254) and compile a constraint system (aka compliance_predicate)
	compliance_predicate_id, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Println("[Generator]: ERROR while compiling constraint system")
		return ProverKeys{}, VerifierKeys{}, User{}
	}

	// Generate PCD Keys from the compliance_predicate
	provingKey, verifyingKey, err := groth16.Setup(compliance_predicate_id)
	if err != nil {
		fmt.Println("[Generator]: ERROR while generating PCD Keys from the constraint system")
		return ProverKeys{}, VerifierKeys{}, User{}
	}

	return ProverKeys{ProvingKey: provingKey, Original_PublicKey: user.PublicKey},
		VerifierKeys{VerifyingKey: verifyingKey, Original_PublicKey: user.PublicKey},
		user
}
