#!/bin/bash
# File organization
find ~/Downloads -name "*.pdf" -exec mv {} ~/Documents/PDFs/ \;
find ~/Downloads -name "*.jpg" -exec mv {} ~/Pictures/ \;
find ~/Downloads -type f -mtime +30 -delete
echo "Files organized"
