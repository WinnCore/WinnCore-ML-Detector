#!/bin/bash
# Error log aggregation
grep ERROR /var/log/app/*.log > /var/log/daily_errors_$(date +%Y%m%d).log
gzip /var/log/daily_errors_*.log
echo "Errors aggregated"
