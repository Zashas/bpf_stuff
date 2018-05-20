#!/bin/bash

gcc inject_dm.c -o inject_dm

for i in {1..15};
do
	./inject_dm fc00::4 4242 fc00::42
	sleep 1
done
