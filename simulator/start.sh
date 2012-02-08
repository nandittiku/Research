#!/bin/bash
num_nodes=100000
check_predecessor_timer=10
let stabilize_timer=2
fix_fingers_timer=2
sign_timer=2
path_timer=10
let mean_alive=3600
simulation_time=1000
random_seed=$RANDOM
rLookup=1
#echo ./sim $num_nodes $check_predecessor_timer $stabilize_timer $fix_fingers_timer $sign_timer $path_timer $mean_alive $simulation_time $random_seed $rLookup
#time ./sim $num_nodes $check_predecessor_timer $stabilize_timer $fix_fingers_timer $sign_timer $path_timer $mean_alive $simulation_time $random_seed $rLookup

for rLookup in 20
do
	echo $rLookup
	time ./sim $num_nodes $check_predecessor_timer $stabilize_timer $fix_fingers_timer $sign_timer $path_timer $mean_alive $simulation_time $random_seed $rLookup > data/lookup/rLookup=$rLookup

done
