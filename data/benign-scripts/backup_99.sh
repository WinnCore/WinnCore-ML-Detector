#!/bin/bash
# File backup
tar czf /backup/files_$(date +%Y%m%d).tar.gz /home/data
rsync -avz /backup/ backup-server:/backups/
echo "Files backed up"
