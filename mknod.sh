#!/bin/sh
# to insmod
# sudo insmod dmm.ko
# to rm
# sudo rmmod dmm.ko
# to mknod, use following
sudo mknod /dev/dmm0 c 99 1

# to check dubug messige
# dmesg > msg.txt
# vi msg.txt
