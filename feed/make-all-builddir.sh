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
                (cd "$dir" && rm go.sum && go mod tidy && make compile) || status=1
            fi
            run_make_recursive "$dir" || status=1
        fi

        if [ "$status" -eq 1 ]; then
            return $status
        fi

    done
    return $status
}

run_make_recursive .

