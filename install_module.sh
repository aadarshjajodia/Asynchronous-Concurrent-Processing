#!/bin/sh
set -x
lsmod
rmmod submitjob
insmod submitjob.ko
lsmod
