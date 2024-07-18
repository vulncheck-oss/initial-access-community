#!/bin/bash

###
# Builds all the exploits leaving behind a `build` directory
###

function run_make_recursive() {
    local status=0
    for dir in "$1"/*; do
        if [ -d "$dir" ] && [ "$(basename "$dir")" != "build" ]; then
            if [ -e "$dir/Makefile" ]; then
                echo "Entering directory: $dir"
                (cd "$dir" && make compile && cp ./build/cve-* /tmp/go-exploit-all) || status=1
            fi
            run_make_recursive "$dir" || status=1
        fi

        if [ "$status" -eq 1 ]; then
            return $status
        fi

    done
    return $status
}

mkdir /tmp/go-exploit-all
run_make_recursive .

