#!/bin/bash
# Cleanup old logs
find /var/log -name "*.log" -mtime +30 -delete
echo "Cleanup complete"
