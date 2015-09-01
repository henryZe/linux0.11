#!/bin/bash

gcc producer.c -o producer
gcc consumer.c -o consumer
/usr/root/producer>p &
/usr/root/consumer>c &
