#!/bin/bash

if [[ "$(whoami)" != root ]]; then
	echo "This script can only be run as root"
	exit 1
fi

userauditing() {
    while read -r F  ; do
        echo "$F"
    done < users.txt

}

userauditing