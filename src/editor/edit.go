package editor

import (
	"fmt"

	"github.com/drakstik/Photognark_V3/src/camera"
	"github.com/drakstik/Photognark_V3/src/photoproof"
)

type Editor struct {
	Editor photoproof.User
}

func (editor Editor) Edit(photo camera.Photograph, tr photoproof.Transformation, params photoproof.Transformation_Parameters) (camera.Photograph, error) {
	z_out, proof_out, err := editor.Editor.Prove(photo.ProverKeys, photo.Z, tr, params, photo.Proof)
	if err != nil {
		fmt.Println("[Edit()] Error while proving an edit")
		return camera.Photograph{}, err
	}

	return camera.Photograph{
		Z:            z_out,
		Proof:        proof_out,
		ProverKeys:   photo.ProverKeys,
		VerifierKeys: photo.VerifierKeys,
	}, err
}
