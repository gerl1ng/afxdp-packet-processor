#!/bin/bash

# This skript sets the interrupt request handling smp_affinity
# of different NIC queues to CPUs on different physical cores
# irq/29 is rx-queue-0 and irq/36 is rx-queue-7 on my machine
# please change the file accordingly to the number of CPU cores
# and the number of rx-queues used.

echo 001 |sudo tee /proc/irq/29/smp_affinity
echo 004 |sudo tee /proc/irq/30/smp_affinity
echo 010 |sudo tee /proc/irq/31/smp_affinity
echo 040 |sudo tee /proc/irq/32/smp_affinity
#echo 100 |sudo tee /proc/irq/33/smp_affinity
#echo 400 |sudo tee /proc/irq/34/smp_affinity
#echo 002 |sudo tee /proc/irq/35/smp_affinity
#echo 008 |sudo tee /proc/irq/36/smp_affinity
