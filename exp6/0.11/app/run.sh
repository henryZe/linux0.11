#!/bin/bash

sudo ~/oslab/mount-hdc
cp * ~/oslab/hdc/usr/root/

if [[ $? -eq 0 ]];
	then cd ~/oslab/linux-0.11; make>/dev/null;
fi

if [[ $? -eq 0 ]];
	then ~/oslab/run;
#	then cd /mnt/hgfs/share/0.11/app; ~/oslab/dbg-c;
fi
