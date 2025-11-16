#!/bin/bash
# Temp file cleanup
find /tmp -type f -mtime +7 -delete
find /var/tmp -type f -mtime +7 -delete
docker system prune -af --volumes
echo "Temp files cleaned"
