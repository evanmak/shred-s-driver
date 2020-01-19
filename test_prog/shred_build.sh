#!/bin/sh
gcc -lpthread shred_wrapper.c shred_test_conc.c dp_malloc.c -o shred_test
