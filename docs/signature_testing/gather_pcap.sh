#!/bin/bash

# Directory to search for pcap files
search_dir="../../feed"

# Directory to move pcap files to
destination_dir="pcaps"

# Check if destination directory exists, if not create it
rm -rf "$destination_dir"
mkdir "$destination_dir"


# Loop through subdirectories and move pcap files
find "$search_dir" -type f \( -name "*.pcap" -o -name "*.pcapng" \) -exec sh -c '
    for pcap; do
        # Get source directory
        src_dir=$(dirname "$pcap")
        
        # Get filename without extension
        file=$(basename "$pcap")
        filename="${file%.*}"

        # Rename pcap file with source directory name
        cp "$pcap" "pcaps/${src_dir##*/}_$filename.${pcap##*.}"
    done
' sh {} +