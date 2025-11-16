#!/bin/bash
# Data processing
for file in /data/input/*.csv; do
    python3 process.py "$file" > "/data/output/$(basename $file)"
done
echo "Data processed"
