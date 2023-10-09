set -ex

# cargo build --example dmsm_test
# BIN=../target/debug/examples/dmsm_test

cargo build --release --example dmsm_test
echo $(ls ../target/release/examples/)
BIN=../target/release/examples/dmsm_test

l=2
t=3
m=32768
n=8

for n_parties in $n
do
  PROCS=""
  i=0
  while [ $i -lt $n_parties ]
  do
    #$BIN $i ./network-address/4 &
    if [ $i -eq 0 ]
    then
      RUST_BACKTRACE=0 RUST_LOG=msm $BIN $i ../network-address/$n_parties $l $t $m &
      pid=$!
      PROCS="$PROCS $pid"
    else
      RUST_LOG=msm $BIN $i ../network-address/$n_parties $l $t $m > /dev/null &
      pid=$!
      PROCS="$PROCS $pid"
    fi
    i=$((i+1))
  done

  for pid in $PROCS
  do
    wait $pid
  done
done

echo done

