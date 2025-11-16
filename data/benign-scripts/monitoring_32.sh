#!/bin/bash
# System health check
df -h > /var/log/disk_usage.log
free -m > /var/log/memory_usage.log
uptime > /var/log/uptime.log
echo "Health check complete"
