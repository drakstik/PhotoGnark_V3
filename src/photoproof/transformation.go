package photoproof

import (
	"github.com/drakstik/Photognark_V3/src/image"
)

type Transformation_Parameters interface {
	GetName() string
	ToFr() Fr_Transformation_Parameters
}

type Transformation interface {
	GetName() string
	Apply(img image.Image, params *Transformation_Parameters) image.Image
}

/*--------------------------------------------Transformation 1------------------------------------------*/
type Identity_Transformation struct{}

func (id_tr Identity_Transformation) GetName() string {
	return "identity"
}

func (id_tr Identity_Transformation) Apply(img image.Image, params *Transformation_Parameters) image.Image {
	return img
}
