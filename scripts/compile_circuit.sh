#!/bin/bash

echo "Compiling test circuit"
mkdir artifacts
~/.cargo/bin/circom --r1cs --wasm --sym \
    -o fixtures/sha256/ \
    fixtures/sha256/sha256.circom

echo -e "Done!\n"
