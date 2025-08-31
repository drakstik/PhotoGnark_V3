package example

import (
	"github.com/drakstik/Photognark_V3/src/camera"
	"github.com/drakstik/Photognark_V3/src/photoproof"
)

func Test_New_Camera() camera.Camera {
	circuit := photoproof.Permissible_Transformations{}
	cam := camera.NewCamera(&circuit)

	return cam
}
