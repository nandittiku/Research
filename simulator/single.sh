#!/bin/bash
num_nodes=10000
check_predecessor_timer=10
let stabilize_timer=2
fix_fingers_timer=3
sign_timer=2
path_timer=10
let mean_alive=3600
simulation_time=1000
rLookup=1
enable_dht_attack=1
single_succ=1

for x in 1 2 3 4 5
do
	random_seed=$RANDOM
	time ./sim $num_nodes $check_predecessor_timer $stabilize_timer $fix_fingers_timer $sign_timer $path_timer $mean_alive $simulation_time $random_seed $rLookup $single_succ $enable_dht_attack > data/dht-many/single-$x.txt
done
