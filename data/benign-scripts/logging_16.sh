#!/bin/bash
# Access log analysis
cat /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -20 > /var/log/top_ips.log
echo "Log analysis complete"
