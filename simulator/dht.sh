#!/bin/bash
num_nodes=1000
check_predecessor_timer=10
let stabilize_timer=2
fix_fingers_timer=5
sign_timer=2
path_timer=10
let mean_alive=3600
simulation_time=1000
random_seed=$RANDOM
rLookup=10
ENABLE_DHT_ATTACK=1
SINGLE_SUCC=0

echo "dht level attack test"
echo time ./sim $num_nodes $check_predecessor_timer $stabilize_timer $fix_fingers_timer $sign_timer $path_timer $mean_alive $simulation_time $random_seed $rLookup $SINGLE_SUCC $ENABLE_DHT_ATTACK
time ./sim $num_nodes $check_predecessor_timer $stabilize_timer $fix_fingers_timer $sign_timer $path_timer $mean_alive $simulation_time $random_seed $rLookup $SINGLE_SUCC $ENABLE_DHT_ATTACK

