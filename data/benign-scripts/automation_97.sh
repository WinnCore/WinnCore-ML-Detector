#!/bin/bash
# Report generation
python3 /opt/scripts/generate_report.py
cp /tmp/report.pdf /var/www/reports/$(date +%Y%m%d)_report.pdf
echo "Report generated"
