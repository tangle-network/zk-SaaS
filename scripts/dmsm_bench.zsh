set -ex
trap "exit" INT TERM
trap "kill 0" EXIT

# cargo build --example dmsm_bench
# BIN=../target/debug/examples/dmsm_bench

cargo build --release --example dmsm_bench
BIN=../target/release/examples/dmsm_bench

l=2
t=3
m=32768
n=8

for n_parties in $n
do
  PROCS=()
  for i in $(seq 0 $(($n_parties - 1)))
  do
    #$BIN $i ./network-address/4 &
    if [ $i == 0 ]
    then
      RUST_BACKTRACE=0 RUST_LOG=msm $BIN $i ../network-address/$n_parties $l $t $m &
      pid=$!
      PROCS[$i]=$pid
    else
      RUST_LOG=msm $BIN $i ../network-address/$n_parties $l $t $m > /dev/null &
      pid=$!
      PROCS[$i]=$pid
    fi
  done
  
  for pid in ${PROCS[@]}
  do
    wait $pid
  done
done

echo done

