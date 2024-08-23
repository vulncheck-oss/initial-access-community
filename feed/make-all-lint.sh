#!/bin/bash

###
# Used to test linting of all projects and used by github actions
###

function run_make_recursive() {
    local status=0
    for dir in "$1"/*; do
        if [ -d "$dir" ] && [ "$(basename "$dir")" != "build" ]; then
            if [ -e "$dir/Makefile" ]; then
                if [ -f "$dir/go.mod" ]; then
                    echo "Entering directory: $dir"
                    (cd "$dir" && rm go.sum && go mod tidy && make all && make clean) || status=1
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

run_make_recursive .
