#!/bin/bash

# Find all directories containing Go test files and run tests
find . -type d | while read dir; do
    if ls "$dir"/*_test.go &> /dev/null; then
        echo "Running tests in: $dir"
        (cd "$dir" && go test ./...)
    fi
done
