package camera

import (
	"fmt"

	"github.com/drakstik/Photognark_V3/src/image"
	"github.com/drakstik/Photognark_V3/src/photoproof"
)

type Photograph struct {
	Z            image.Z
	Proof        photoproof.Proof
	ProverKeys   photoproof.ProverKeys
	VerifierKeys photoproof.VerifierKeys
}

type Camera struct {
	Admin       photoproof.User
	Photographs []Photograph
	Prover      photoproof.ProverKeys
	Verifier    photoproof.VerifierKeys
}

func NewCamera(circuit *photoproof.Permissible_Transformations) Camera {
	prover, verifier, admin := photoproof.Generator(circuit)
	return Camera{
		Admin:       admin,
		Photographs: []Photograph{},
		Prover:      prover,
		Verifier:    verifier,
	}
}

func (cam *Camera) TakePhotograph(flag string) (Photograph, error) {
	img, err := image.NewImage("random")
	if err != nil {
		fmt.Println("[TakePhotograph()] Error while creating a NewImage()")
		return Photograph{}, err
	}

	signature, err := cam.Admin.Sign(img)
	if err != nil {
		fmt.Println("[TakePhotograph()] Error while signing a new image")
		return Photograph{}, err
	}

	photo := Photograph{
		Z: image.Z{
			Img:               img,
			PublicKey:         cam.Admin.PublicKey,
			OriginalSignature: signature,
			OriginalHash:      img.Hash(),
		},
		Proof: photoproof.Proof{
			PCD_Proof: nil, // No PCD_Proof yet.
			Signature: signature,
		},
		ProverKeys:   cam.Prover,
		VerifierKeys: cam.Verifier,
	}

	cam.Photographs = append(cam.Photographs, photo)

	return photo, err
}
