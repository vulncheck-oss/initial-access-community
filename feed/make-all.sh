#!/bin/bash

function run_make_recursive() {
    for dir in "$1"/*; do
        if [ -d "$dir" ] && [ "$(basename "$dir")" != "build" ]; then
            if [ -e "$dir/Makefile" ]; then
                echo "Entering directory: $dir"
                (cd "$dir" && make "$MAKE_TARGET")
            fi
            run_make_recursive "$dir"
        fi
    done
}

start_dir="."
MAKE_TARGET="all"

if [ "$1" == "clean" ]; then
    MAKE_TARGET="clean"
fi

run_make_recursive "$start_dir"

