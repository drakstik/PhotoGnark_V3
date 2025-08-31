package example

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

/*
This file contains a test circuit to explore how Gnark circuits are written,
compiled, used to generate PCD keys, create witnesses, proofs and
verify proofs.
*/
type Test_Circuit struct {
	SecretNumber frontend.Variable `gnark:",secret"`
	PublicNumber frontend.Variable `gnark:",public"`
}

// This circuit will simply check if the public number is equal to the secret number.
func (circuit *Test_Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(circuit.SecretNumber, circuit.PublicNumber)

	// If you comment out this part, the secret number can be any number the prover wants.
	api.AssertIsEqual(circuit.SecretNumber, 123456789) // secret number must be 123456789

	return nil
}

type Test_ProverKeys struct {
	ProvingKey groth16.ProvingKey
}

type Test_VerifierKeys struct {
	VerifyingKey groth16.VerifyingKey
}

func Test_Generator(circuit *Test_Circuit) (Test_ProverKeys, Test_VerifierKeys, error) {
	// Set the security parameter (BN254) and compile a constraint system (aka compliance_predicate)
	compliance_predicate_id, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Println("[Generator]: ERROR while compiling constraint system")
		return Test_ProverKeys{}, Test_VerifierKeys{}, err
	}

	// Generate PCD Keys from the compliance_predicate
	provingKey, verifyingKey, err := groth16.Setup(compliance_predicate_id)
	if err != nil {
		fmt.Println("[Generator]: ERROR while generating PCD Keys from the constraint system")
		return Test_ProverKeys{}, Test_VerifierKeys{}, err
	}

	fmt.Println("********Test_Generator was successful!********")
	return Test_ProverKeys{ProvingKey: provingKey},
		Test_VerifierKeys{VerifyingKey: verifyingKey}, err
}

func Test_Admin(n int64) (Test_ProverKeys, Test_VerifierKeys, error) {
	admin_circuit := Test_Circuit{
		SecretNumber: frontend.Variable(n),
		PublicNumber: frontend.Variable(n),
	}

	return Test_Generator(&admin_circuit)
}

// Create proof that prover knows the secret n.
func Test_Prover(n int64, pr_k Test_ProverKeys, vk Test_VerifierKeys) (groth16.Proof, error) {
	prover_circuit := Test_Circuit{
		SecretNumber: frontend.Variable(n),
		PublicNumber: frontend.Variable(n), // TODO: Try it with just Y.
	}

	// Create the secret witness from the circuit (runs Define())
	secret_witness_out, err := frontend.NewWitness(&prover_circuit, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}

	// Set the security parameter and compile a constraint system (aka compliance_predicate) (runs Define())
	compliance_predicate, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &prover_circuit)
	if err != nil {
		return nil, err
	}

	// Create pcd_proof_out that the secret witness adheres to the compliance predicate, using the given proving key (runs Define())
	pcd_proof_out, err := groth16.Prove(compliance_predicate, pr_k.ProvingKey, secret_witness_out)
	if err != nil {
		return nil, err
	}

	fmt.Println("********Test_Prover was successful!********")

	return pcd_proof_out, err
}

// Verify that Verifier knows the secret n.
func Test_Verifier(n int64, proof_in groth16.Proof, pr_k Test_ProverKeys, vk Test_VerifierKeys) (bool, error) {
	assignment := Test_Circuit{
		SecretNumber: 102, // The secret value does not matter if you are verifying, but it cannot be nil.
		PublicNumber: n,   // assign only the public variable
	}

	// Create the secret witness from the circuit (runs Define())
	// Recreate a secret witness
	secret_witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("ERROR: frontend.NewWitness() while creating witness...\n" + err.Error())
		return false, err
	}

	// Recreate the public witness
	public_witness, err := secret_witness.Public()
	if err != nil {
		fmt.Println("ERROR: secret_witness.Public() while verifying proof..")
		return false, err
	}

	// Verify the proof with the recreated public witness and verifying key
	err = groth16.Verify(proof_in, vk.VerifyingKey, public_witness)
	if err != nil {
		fmt.Println("ERROR: VerifyGnarkProof failed.")
		return false, err
	}

	fmt.Println("********Test_Verifier was successful!********")
	return true, err
}

func Test_Partial_Knowledge(prover_knowledge bool, verifier_knowledge bool) {
	// Admin
	init_circuit := Test_Circuit{}
	pr_k, vk, err := Test_Generator(&init_circuit)
	if err != nil {
		fmt.Println("Test_Generator failed!")
		return
	}

	var n int64

	if prover_knowledge {
		n = int64(123456789)
	} else {
		n = int64(12345678)
	}

	// Prover with full knowledge of n [Should not work...]
	proof, err := Test_Prover(n, pr_k, vk)
	if err != nil {
		fmt.Println("Test_Prover failed!")
		return
	}

	if verifier_knowledge {
		n = int64(123456789)
	} else {
		n = int64(1234567)
	}

	// Verifier with full knowledge of n [Should not work...]
	ok, err := Test_Verifier(n, proof, pr_k, vk)
	if err != nil {
		fmt.Println("Test_Verifier failed!")
		return
	}

	if ok {
		return
	} else {
		fmt.Println("Test_Verifier failed!")
	}
}
