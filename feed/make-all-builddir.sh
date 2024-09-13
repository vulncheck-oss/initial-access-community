#!/bin/bash

###
# Builds all the exploits leaving behind a `build` directory
###

function run_make_recursive() {
    local status=0
    for dir in "$1"/*; do
        if [ -d "$dir" ] && [ "$(basename "$dir")" != "build" ]; then
            if [ -e "$dir/Makefile" ]; then
                if [ -f "$dir/go.mod" ]; then
                    echo "Entering directory: $dir"
                    (cd "$dir" && make compile) || status=1
                    for file in "$dir/build/cve-"*; do
                        if [ -f "$file" ]; then
                            # handle duplicate filenames by slapping a timestamp onto each binary
                            filename=$(basename "$file")
                            timestamp=$(date +%s%N)
                            new_filename="${filename%.*}-$timestamp"
                            cp "$file" "/tmp/go-exploit-all/$new_filename"
                        fi
                    done
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

mkdir -p /tmp/go-exploit-all
run_make_recursive .