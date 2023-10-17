trap "exit" INT TERM
trap "kill 0" EXIT
set -ex
cargo build --example dpp_test
BIN=../target/debug/examples/dpp_test

# cargo build --release --example dpp_test
# BIN=../target/release/examples/dpp_test

l=2
t=3
m=16
n=8

for n_parties in $n
do
  PROCS=()
  for i in $(seq 0 $(($n_parties - 1)))
  do
    #$BIN $i ./network-address/4 &
    if [ $i == 0 ]
    then
      RUST_BACKTRACE=0 RUST_LOG=fft $BIN $i ../network-address/$n_parties $l $t $m &
      pid=$!
      PROCS[$i]=$pid
    else
      RUST_LOG=fft $BIN $i ../network-address/$n_parties $l $t $m > /dev/null &
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

