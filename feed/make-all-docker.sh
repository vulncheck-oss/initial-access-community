#!/bin/bash

###
# Uses the exploits dockerfile to generate images for everything
###

function run_make_recursive() {
    local status=0
    for dir in "$1"/*; do
        if [ -d "$dir" ] && [ "$(basename "$dir")" != "build" ]; then
            if [ -e "$dir/Makefile" ]; then
                if [ -f "$dir/go.mod" ]; then
                    echo "Entering directory: $dir"
                    (cd "$dir" && make "$MAKE_TARGET" && make clean) || status=1
                fi
            fi
            run_make_recursive "$dir" || status=1
        fi

        if [ "$status" -eq 1 ]; then
            return $status
        fi

    done
    return $status
}

MAKE_TARGET="docker"

run_make_recursive .

