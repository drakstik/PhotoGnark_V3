package image

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/signature/eddsa"
)

const N uint64 = 5
const N2 uint64 = N * N // Total number of pixels in an image is N*N

/*-------------------------------------------- Pixel Construction --------------------------------------------*/

// The (x,y) location of a pixel
type PixelLocation struct {
	X uint64 // X dimenstion of a 2D matrix
	Y uint64 // Y dimension of a 2D matrix
}

func (loc PixelLocation) To_1D_Index() uint64 {
	return loc.Y*N + loc.X
}

// A pixel
type Pixel struct {
	RGB [3]uint8      // Array representation
	Loc PixelLocation // Pixel's 2D location
}

// Turn pixel to the gnark-friendly version of a pixel: Fr_Pixel.
func (pxls Pixel) ToFr() Fr_Pixel {
	return Fr_Pixel{
		RGB: [3]frontend.Variable{pxls.RGB[0], pxls.RGB[1], pxls.RGB[2]},
		Loc: Fr_PixelLocation{
			X: pxls.Loc.X,
			Y: pxls.Loc.Y,
		},
	}
}

/*-------------------------------------------- Image Construction -------------------------------------------*/
// An image
type Image struct {
	Pxls [N2]Pixel // Array
}

// Write Image's values (RGB & Location) into a hash.StateStorer and return its hash.
// Each value is set as the z-value of a field element, and appended to the hash.StateStorer as a
// big-endian slice representation of the z-value.
func (img Image) Hash() []byte {

	msg := mimc.NewMiMC()

	var fr fr.Element // New field element
	absorb := func(u uint64) {
		fr.SetUint64(u)                            // Set z value of the field element to a uint64
		ZValue_as_big_endian_slice := fr.Marshal() // big-endian slice representation of z value
		msg.Write(ZValue_as_big_endian_slice)      // Append big-endian slice directly into message; before hashing
	}

	for i := 0; i < int(N2); i++ {
		px := img.Pxls[i]
		absorb(uint64(px.RGB[0]))
		absorb(uint64(px.RGB[1]))
		absorb(uint64(px.RGB[2]))
		absorb(px.Loc.X)
		absorb(px.Loc.Y)
	}

	return msg.Sum(nil) // Hash the current message return the hash
}

// Turn this Image to its gnark-friendly version: Fr_Image
func (img Image) ToFr() Fr_Image {
	// Create new Fr_Image
	fr_image := Fr_Image{
		Pxls: [N2]Fr_Pixel{},
	}

	// For each index i, set fr_image[i] to a Fr version of the pixel in img[i]
	for i := 0; i < int(N2); i++ {
		fr_image.Pxls[i] = img.Pxls[i].ToFr()
	}

	return fr_image
}

func (img Image) PrintImage() {
	for row := 0; row < int(N); row++ {
		fmt.Print("[")
		for col := 0; col < int(N); col++ {
			idx := row*int(N) + col
			pixel := img.Pxls[idx]
			r, g, b := pixel.RGB[0], pixel.RGB[1], pixel.RGB[2]

			fmt.Printf("(%d,%d,%d)", r, g, b)

			if col != int(N)-1 {
				fmt.Print(", ")
			}
		}
		fmt.Println("]")
	}
}

/*-------------------------------------------- Z Construction -------------------------------------------*/
// Z = (Image, Public Key)
type Z struct {
	Img       Image
	PublicKey signature.PublicKey
	// Original signature and hash
	OriginalSignature []byte
	OriginalHash      []byte
}

func (z Z) ToFr() Fr_Z {
	// Assign the PK & SK to their eddsa equivilant
	var eddsa_digSig eddsa.Signature
	var eddsa_PK eddsa.PublicKey

	eddsa_digSig.Assign(1, z.OriginalSignature)
	eddsa_PK.Assign(1, z.PublicKey.Bytes())

	return Fr_Z{
		Img:               z.Img.ToFr(),
		PublicKey:         eddsa_PK,
		OriginalSignature: eddsa_digSig,
		OriginalHash:      frontend.Variable(z.OriginalHash),
	}
}

/*----------------------------------------------- Area Construction -------------------------------------*/
// Represents an area inside an image.
type Area struct {
	Loc    PixelLocation
	Width  uint64 // Starting at 1
	Height uint64 // Starting at 1
}
