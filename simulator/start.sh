#!/bin/bash
num_nodes=30
check_predecessor_timer=10
stabilize_timer=2
fix_fingers_timer=2
sign_timer=20
path_timer=10
mean_alive=30
simulation_time=1000
random_seed=1 
#$RANDOM
echo ./sim $num_nodes $check_predecessor_timer $stabilize_timer $fix_fingers_timer $sign_timer $path_timer $mean_alive $simulation_time $random_seed
time ./sim $num_nodes $check_predecessor_timer $stabilize_timer $fix_fingers_timer $sign_timer $path_timer $mean_alive $simulation_time $random_seed


