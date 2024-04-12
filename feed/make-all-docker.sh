#!/bin/bash

###
# Uses the exploits dockerfile to generate images for everything
###

function run_make_recursive() {
    for dir in "$1"/*; do
        if [ -d "$dir" ] && [ "$(basename "$dir")" != "build" ]; then
            if [ -e "$dir/Makefile" ]; then
                echo "Entering directory: $dir"
                (cd "$dir" && make "$MAKE_TARGET" && make clean)
            fi
            run_make_recursive "$dir"
        fi
    done
}

MAKE_TARGET="docker"

run_make_recursive .

