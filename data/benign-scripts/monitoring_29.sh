#!/bin/bash
# CPU and memory monitoring
top -bn1 | head -20 > /var/log/top_output.log
ps aux --sort=-%mem | head -10 > /var/log/memory_hogs.log
echo "Resource monitoring done"
