PTAU_PATH=./powersOfTau28_hez_final_22.ptau

if [ ! -f $PTAU_PATH ]; then
    echo "PTAU file not found, downloading..."
    curl -O https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_22.ptau
fi

compile_phase2 () {
    local outdir="$1" circuit="$2" pathToCircuitDir="$3"
    echo $outdir;
    mkdir -p $outdir;

    echo "Setting up Phase 2 ceremony for $circuit"
    echo "Outputting circuit_final.zkey and verifier.sol to $outdir"

    npx snarkjs groth16 setup "$pathToCircuitDir/$circuit.r1cs" $PTAU_PATH "$outdir/circuit_0000.zkey"
    echo "test" | npx snarkjs zkey contribute "$outdir/circuit_0000.zkey" "$outdir/circuit_0001.zkey" --name"1st Contributor name" -v
    npx snarkjs zkey verify "$pathToCircuitDir/$circuit.r1cs" $PTAU_PATH "$outdir/circuit_0001.zkey"
    npx snarkjs zkey beacon "$outdir/circuit_0001.zkey" "$outdir/circuit_final.zkey" 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2"
    npx snarkjs zkey verify "$pathToCircuitDir/$circuit.r1cs" $PTAU_PATH "$outdir/circuit_final.zkey"
    npx snarkjs zkey export verificationkey "$outdir/circuit_final.zkey" "$outdir/verification_key.json"  

    npx snarkjs zkey export solidityverifier "$outdir/circuit_final.zkey" $outdir/verifier.sol
    echo "Done!\n"
}

compile_phase2 "fixtures" "sha256" "fixtures/sha256"
