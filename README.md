# Cryptographic Cryptid Protocols
## How to Play Cryptid with Cheaters
This repository provides an implementation of the main algorithms of our cryptographic cryptid protocols.
We evaluate the performance (in terms of time and size) of the GenClue, OpenClue, Play and Verify algorithms for the CC1 and CC2 schemes, and the ProveGame and VerifyGame algorithms for the VCC scheme. The measurements allow the calculation of the required memory and latency to play the game online.
We use the Ristretto prime order group with the curve25519_dalek library: https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ .

## Use
Our implementation is divided into three folders: scheme1, scheme2 and schemevcc, each containing the files "main.rs", "zkp.rs", "lib.rs", "cargo.lock" and "cargo.toml".
To compile the code in the scheme1 folder (or scheme2, schemevcc), open a terminal in the appropriate folder and use the `cargo build --release` command in the terminal, then the `cargo run --release` command is used to run the corresponding code.
The `cargo run` command runs the "main.rs" file, which starts the performance measurements over a configurable number of iterations (named "iter" in "main.rs").
The "lib.rs" file contains tests for the correct operation of the GenClue, OpenClue, Play, Verify, ProveGame and VerifyGame algorithms. The `cargo test` command is used to run these tests.

