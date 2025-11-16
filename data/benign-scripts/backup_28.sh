#!/bin/bash
# Incremental backup
rsync -avz --delete /var/www/ /backup/www/
tar czf /backup/incremental_$(date +%Y%m%d_%H%M).tar.gz /backup/www/
echo "Incremental backup done"
