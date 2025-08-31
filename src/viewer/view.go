package viewer

import (
	"fmt"

	"github.com/drakstik/Photognark_V3/src/camera"
	"github.com/drakstik/Photognark_V3/src/photoproof"
)

type Viewer struct {
	Viewer photoproof.User
}

func (v Viewer) View(photo camera.Photograph) error {
	// Run photoproof.Verify() on the given photograph
	ok, err := v.Viewer.Verify(photo.VerifierKeys, photo.Z, photo.Proof)
	if err != nil {
		return err
	}

	// Display image if successful
	if ok {
		fmt.Println("********Viewer SUCCESSFUL viewed photo********")
		photo.Z.Img.PrintImage()
		return nil
	} else { // Do not display image if unsuccessful
		fmt.Println("********Viewer FAILED to view photo********")
	}

	return nil
}
