#!/bin/sh

sudo /home/henry/oslab/mount-hdc
cp /home/henry/oslab/hdc/var/dis_func.log ./
cp /home/henry/oslab/hdc/var/process.log ./
./stat_log.py /home/henry/Desktop/work/exp3_1/process.log 6 7 8 9 10
