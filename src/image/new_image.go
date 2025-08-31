package image

import (
	"crypto/rand"
	"math/big"
)

func NewImage(flag string) (Image, error) {
	newImage := Image{Pxls: [N2]Pixel{}}

	for row := 0; row < int(N); row++ {
		for col := 0; col < int(N); col++ {
			if flag == "black" {
				// Translate the 2D location (x,y) into a 1D index.
				idx := row*int(N) + col
				black := [3]uint8{0, 0, 0}

				blackPixel := Pixel{
					RGB: black,
					Loc: PixelLocation{X: uint64(col), Y: uint64(row)},
				}

				newImage.Pxls[idx] = blackPixel
			}

			if flag == "white" {
				// Translate the 2D location (x,y) into a 1D index.
				idx := row*int(N) + col
				white := [3]uint8{255, 255, 255}

				whitePixel := Pixel{
					RGB: white,
					Loc: PixelLocation{X: uint64(col), Y: uint64(row)},
				}

				newImage.Pxls[idx] = whitePixel
			}

			if flag == "random" {
				// Generate a random number between 0 and 255
				n1, err := rand.Int(rand.Reader, big.NewInt(256))
				if err != nil {
					return Image{}, err
				}
				n2, err := rand.Int(rand.Reader, big.NewInt(256))
				if err != nil {
					return Image{}, err
				}
				n3, err := rand.Int(rand.Reader, big.NewInt(256))
				if err != nil {
					return Image{}, err
				}

				random := [3]uint8{uint8(n1.Int64()), uint8(n2.Int64()), uint8(n3.Int64())}

				// Translate the 2D location (x,y) into a 1D index.
				idx := row*int(N) + col

				randomPixel := Pixel{
					RGB: random,
					Loc: PixelLocation{X: uint64(col), Y: uint64(row)},
				}

				newImage.Pxls[idx] = randomPixel
			}
		}
	}

	return newImage, nil
}
