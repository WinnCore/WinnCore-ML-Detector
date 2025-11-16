#!/bin/bash
# Log rotation and cleanup
find /var/log -name "*.log" -mtime +30 -delete
journalctl --vacuum-time=30d
apt autoremove -y
echo "Cleanup complete"
