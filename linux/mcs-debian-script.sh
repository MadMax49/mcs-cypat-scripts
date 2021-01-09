#!/bin/bash

if [[ "$(whoami)" != root ]]
then
	echo "This script can only be run as root"
	exit 1
fi