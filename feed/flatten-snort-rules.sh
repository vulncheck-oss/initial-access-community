# Set the output file for the combined rules
OUTPUT_FILE="vulncheck.snort.rules"

# Find all files with the .suricata.rule extension and concatenate them into one file
find . -type f -name "*.snort.rule" -exec cat {} + > "$OUTPUT_FILE"

# Add a newline after each closing parenthesis followed by "alert"
sed -i 's/)\(alert\)/)\n\1/g' "$OUTPUT_FILE"

# Remove leading and trailing whitespace
sed -i 's/^[[:space:]]*//; s/[[:space:]]*$//' "$OUTPUT_FILE"

# Flatten each rule to a single line
sed -i ':a;N;$!ba;s/\\\n//g' "$OUTPUT_FILE"

# Replace lines starting with # with an empty line
sed -i '/^#/ s/.*/ /' "$OUTPUT_FILE"

# Remove empty lines
sed -i '/^$/d' "$OUTPUT_FILE"

# Extract SIDs and check for duplicates
awk -F'sid:' '/sid:/ {sid=$2; sub(/;.*/, "", sid); if (sid in sids) { print "Error: Duplicate SID " sid " detected."; exit 1 } else { sids[sid] } }' "$OUTPUT_FILE"

# Extract SIDs and sort rules by SID in descending order
awk -F'sid:' '{print $2}' "$OUTPUT_FILE" | awk -F';' '{print $1}' | sort -n | while read -r sid; do grep "sid:$sid;" "$OUTPUT_FILE"; done > sorted_"$OUTPUT_FILE"
mv sorted_"$OUTPUT_FILE" "$OUTPUT_FILE"
