#!/bin/bash
# Generate usage report
echo "=== System Report $(date) ===" > /tmp/report.txt
df -h >> /tmp/report.txt
free -m >> /tmp/report.txt
uptime >> /tmp/report.txt
mail -s "Daily Report" admin@example.com < /tmp/report.txt
echo "Report sent"
