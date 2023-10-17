#!/bin/bash
trap "exit" INT TERM
trap "kill 0" EXIT
set -ex
echo "Generating certificates..."
n=5 # number of key/cert pairs to generate
king_addr="localhost:12344"

mkdir -p ./certs
for i in $(seq 0 $((n-1))); do
  cargo run --example gen_cert -- ./certs/public_$i.cert.der ./certs/private_$i.key.der localhost
done

cargo build --release --example add_ids
BIN=$(git rev-parse --show-toplevel)/target/release/examples/add_ids

for n_parties in $n
do
  PROCS=()
  for i in $(seq 0 $(($n_parties - 1)))
  do
    #$BIN $i ./network-address/4 &
    if [ $i == 0 ]
    then
      # Setup king
      RUST_BACKTRACE=0 RUST_LOG=fft $BIN ./certs/public_$i.cert.der ./certs/private_$i.key.der --id $i --n-parties $n  --bind-addr $king_addr --client-cert-dir ./certs &
      pid=$!
      PROCS[$i]=$pid
      sleep 1
    else
      # Setup basic node
      RUST_LOG=fft $BIN ./certs/public_$i.cert.der ./certs/private_$i.key.der --id $i --n-parties $n --king-addr $king_addr --king-cert ./certs/public_0.cert.der > /dev/null &
      pid=$!
      PROCS[$i]=$pid
    fi
  done

  for pid in ${PROCS[@]}
  do
    wait $pid || exit 1
  done
done

echo done