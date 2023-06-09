set -ex
trap "exit" INT TERM
trap "kill 0" EXIT

file=dpoly_commit_test
cargo build --example $file
BIN=../target/debug/examples/$file

# cargo build --release --example $file
# BIN=../target/release/examples/$file

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
      RUST_BACKTRACE=0 RUST_LOG=poly_commit $BIN $i ../network-address/$n_parties $l $t $m &
      pid=$!
      PROCS[$i]=$pid
    else
      RUST_LOG=poly_commit $BIN $i ../network-address/$n_parties $l $t $m > /dev/null &
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

