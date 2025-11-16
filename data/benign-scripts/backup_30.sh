#!/bin/bash
# Database backup script
DATE=$(date +%Y%m%d)
mysqldump -u backup dbname > /backup/db_$DATE.sql
gzip /backup/db_$DATE.sql
find /backup -name "*.gz" -mtime +30 -delete
echo "Backup completed"
