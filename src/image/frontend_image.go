package image

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

/*------------------------------------------ Gnark-Friendly Pixel --------------------------------------*/

type Fr_PixelLocation struct {
	X frontend.Variable `gnark:",inherit"` // X dimenstion of a 2D matrix
	Y frontend.Variable `gnark:",inherit"` // Y dimension of a 2D matrix
}

func (loc Fr_PixelLocation) To_1D_Index(api frontend.API) frontend.Variable {
	return api.Add(api.Mul(loc.Y, frontend.Variable(N)), loc.X)
}

type Fr_Pixel struct {
	RGB [3]frontend.Variable `gnark:",inherit"` // Array representation
	Loc Fr_PixelLocation     `gnark:",inherit"` // Pixel's location
}

/*------------------------------------------ Gnark-Friendly Image --------------------------------------*/

// An Fr_Image is an image that is gnark-friendly.
type Fr_Image struct {
	Pxls [N2]Fr_Pixel `gnark:",inherit"`
}

// Hash function for an Fr_Image.
// This function must have mirror output to the Image.Hash() function.
func (img Fr_Image) Hash(api frontend.API) (frontend.Variable, mimc.MiMC) {
	data := make([]frontend.Variable, 0, N2*5) // New frontend.Variable slice; each pixel: 3 RGB + row + col
	for i := 0; i < int(N2); i++ {
		px := img.Pxls[i]
		data = append(data,
			px.RGB[0], px.RGB[1], px.RGB[2], // Append RGB values
			px.Loc.X, px.Loc.Y, // Append location values
		)
	}

	// Hash the serialized z.Img (Use MiMC).
	h, _ := mimc.NewMiMC(api)
	h.Write(data)
	digest := h.Sum()
	return digest, h
}

/*------------------------------------------ Gnark-Friendly Z --------------------------------------*/
type Fr_Z struct {
	Img       Fr_Image
	PublicKey eddsa.PublicKey
	// Original signature and hash
	OriginalSignature eddsa.Signature
	OriginalHash      frontend.Variable
}

/*------------------------------------------ Gnark-Friendly Area --------------------------------------*/
// Represents an area inside an Fr_Image.
type Fr_Area struct {
	Loc    Fr_PixelLocation
	Width  frontend.Variable // Starting at 1
	Height frontend.Variable // Starting at 1
}
