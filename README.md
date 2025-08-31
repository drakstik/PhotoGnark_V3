# PhotoGnark V3

This is a project that I am undertaking as a presentation at the Africa Cyber Defense Forum, 2025 in Kigali.

PhotoGnark is a Golang implementation of [PhotoProof](https://ieeexplore.ieee.org/document/7546506) that leverages the [Gnark](https://docs.gnark.consensys.io/) package for Zero Knowledge cryptographic functionality.


# PhotoGnark: A Quick Introduction
To achieve *Image Authentication*, even after an image has underwent multiple *permissible transformations*, the paper by Assa Naveh and Eran Tromer, from Tel Aviv University, proposes a cryptographic scheme that combines a digital signature scheme and the typical ZK-SNARKs algorithms commonly known as the Generator, Prover and Verifier schemes to define permissible transformations for images taken with a Secure Camera. This scheme is called PhotoProof.

## What is Image Authentication?

To achieve Image Authentication, we first need a **Secure Camera**. 

A Secure Camera is a camera that can securely take an image and sign the image. This means that the Secure Camera is immune to hardware tempering, side channels and image injection attacks. 


Here are some important definitions:

**Original Image:** An image is said to be *original* if its ZK-SNARK proof was signed by a Secure Camera using a secure signature scheme. 

**Permissible Provenance:** An image is said to have a permissible provenance if it has proveably undergone *only* permissible transformations, as defined by circuits and a constraint system (aka compliance predicate).

**Authentic Image:** An image *t_n* is said to be *authentic* if it has a permissible provenance and is an original image O (*O,t1,t2,t3,...t_n*) .


# What is an Image object?
### What is a Pixel object?


# What is a Transformation vs. a Permissible Transformation?
### In-Circuit vs. Out-of-Circuit


# Main Circuit

## What does the Main Circuit Assert?
### Verify_Original_Signature()
### Check_Transformation()
## What is the Prover Proving?
## What is the Verifier Verifying?

