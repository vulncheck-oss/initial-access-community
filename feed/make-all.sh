#!/bin/bash

function run_make_recursive() {
    local status=0
    for dir in "$1"/*; do
        if [ -d "$dir" ] && [ "$(basename "$dir")" != "build" ]; then
            if [ -e "$dir/Makefile" ]; then
                echo "Entering directory: $dir"
                (cd "$dir" && rm go.sum && go mod tidy && make "$MAKE_TARGET" && make clean) || status=1
            fi
            run_make_recursive "$dir" || status=1
        fi

        if [ "$status" -eq 1 ]; then
            return $status
        fi

    done
    return $status
}

start_dir="."
MAKE_TARGET="compile"

run_make_recursive "$start_dir"

