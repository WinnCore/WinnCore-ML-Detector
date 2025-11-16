#!/bin/bash
# Database maintenance
psql -U postgres -c "VACUUM ANALYZE;"
mysql -u root -e "OPTIMIZE TABLE users;"
echo "Database optimized"
