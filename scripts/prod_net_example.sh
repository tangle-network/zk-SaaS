#!/bin/bash
trap "exit" INT TERM
trap "kill 0" EXIT
set -ex
echo "Generating certificates..."
n=5 # number of key/cert pairs to generate
king_addr="127.0.0.1:12344"

mkdir -p ./certs
for i in $(seq 0 $((n-1))); do
  if [ $i -eq 0 ]; then
    cargo run --example gen_cert -- ./public_$i.cert.der ./private_$i.key.der "127.0.0.1"
  else
    cargo run --example gen_cert -- ./certs/public_$i.cert.der ./certs/private_$i.key.der "127.0.0.1"
  fi

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
      RUST_BACKTRACE=0 RUST_LOG=fft $BIN ./public_$i.cert.der ./private_$i.key.der --id $i --n-parties $n  --bind-addr $king_addr --client-cert-dir ./certs &
      pid=$!
      PROCS[$i]=$pid
      sleep 1
    else
      # Setup basic node
      RUST_LOG=fft $BIN ./certs/public_$i.cert.der ./certs/private_$i.key.der --id $i --n-parties $n --king-addr $king_addr --king-cert ./public_0.cert.der > /dev/null &
      pid=$!
      PROCS[$i]=$pid
    fi
  done

  for pid in ${PROCS[@]}
  do
    wait $pid || { echo "Process $pid exited with an error status"; exit 1; }
  done
done

echo done