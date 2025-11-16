#!/usr/bin/env python3
"""Generate legitimate benign bash scripts for training"""

from pathlib import Path
import random

class BenignScriptGenerator:
    def __init__(self):
        self.output_dir = Path("data/benign-scripts")
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_all(self):
        categories = [
            ("backup", self.generate_backup, 100),
            ("monitoring", self.generate_monitoring, 100),
            ("deployment", self.generate_deployment, 100),
            ("maintenance", self.generate_maintenance, 100),
            ("automation", self.generate_automation, 100),
            ("logging", self.generate_logging, 100),
            ("reporting", self.generate_reporting, 100),
        ]
        
        total = 0
        for category, generator, count in categories:
            print(f"Generating {count} {category} scripts...")
            for i in range(count):
                generator(i)
                total += 1
        
        print(f"\n✅ Generated {total} benign scripts")
        return total
    
    def generate_backup(self, idx):
        scripts = [
            """#!/bin/bash
# Database backup script
DATE=$(date +%Y%m%d)
mysqldump -u backup dbname > /backup/db_$DATE.sql
gzip /backup/db_$DATE.sql
find /backup -name "*.gz" -mtime +30 -delete
echo "Backup completed"
""",
            """#!/bin/bash
# File backup
tar czf /backup/files_$(date +%Y%m%d).tar.gz /home/data
rsync -avz /backup/ backup-server:/backups/
echo "Files backed up"
""",
            """#!/bin/bash
# Incremental backup
rsync -avz --delete /var/www/ /backup/www/
tar czf /backup/incremental_$(date +%Y%m%d_%H%M).tar.gz /backup/www/
echo "Incremental backup done"
""",
        ]
        self.write_script(f"backup_{idx}.sh", random.choice(scripts))
    
    def generate_monitoring(self, idx):
        scripts = [
            """#!/bin/bash
# System health check
df -h > /var/log/disk_usage.log
free -m > /var/log/memory_usage.log
uptime > /var/log/uptime.log
echo "Health check complete"
""",
            """#!/bin/bash
# Service monitoring
systemctl status nginx > /dev/null || systemctl restart nginx
systemctl status postgresql > /dev/null || systemctl restart postgresql
echo "Services checked"
""",
            """#!/bin/bash
# CPU and memory monitoring
top -bn1 | head -20 > /var/log/top_output.log
ps aux --sort=-%mem | head -10 > /var/log/memory_hogs.log
echo "Resource monitoring done"
""",
        ]
        self.write_script(f"monitoring_{idx}.sh", random.choice(scripts))
    
    def generate_deployment(self, idx):
        scripts = [
            """#!/bin/bash
# Application deployment
cd /var/www/app
git pull origin main
npm install
npm run build
pm2 restart app
echo "Deployment complete"
""",
            """#!/bin/bash
# Docker deployment
docker pull myapp:latest
docker stop myapp-container || true
docker rm myapp-container || true
docker run -d --name myapp-container -p 8080:8080 myapp:latest
echo "Container deployed"
""",
            """#!/bin/bash
# Static site deployment
cd /var/www/site
git pull
bundle install
jekyll build
systemctl reload nginx
echo "Site deployed"
""",
        ]
        self.write_script(f"deployment_{idx}.sh", random.choice(scripts))
    
    def generate_maintenance(self, idx):
        scripts = [
            """#!/bin/bash
# Log rotation and cleanup
find /var/log -name "*.log" -mtime +30 -delete
journalctl --vacuum-time=30d
apt autoremove -y
echo "Cleanup complete"
""",
            """#!/bin/bash
# Database maintenance
psql -U postgres -c "VACUUM ANALYZE;"
mysql -u root -e "OPTIMIZE TABLE users;"
echo "Database optimized"
""",
            """#!/bin/bash
# Temp file cleanup
find /tmp -type f -mtime +7 -delete
find /var/tmp -type f -mtime +7 -delete
docker system prune -af --volumes
echo "Temp files cleaned"
""",
        ]
        self.write_script(f"maintenance_{idx}.sh", random.choice(scripts))
    
    def generate_automation(self, idx):
        scripts = [
            """#!/bin/bash
# File organization
find ~/Downloads -name "*.pdf" -exec mv {} ~/Documents/PDFs/ \;
find ~/Downloads -name "*.jpg" -exec mv {} ~/Pictures/ \;
find ~/Downloads -type f -mtime +30 -delete
echo "Files organized"
""",
            """#!/bin/bash
# Report generation
python3 /opt/scripts/generate_report.py
cp /tmp/report.pdf /var/www/reports/$(date +%Y%m%d)_report.pdf
echo "Report generated"
""",
            """#!/bin/bash
# Data processing
for file in /data/input/*.csv; do
    python3 process.py "$file" > "/data/output/$(basename $file)"
done
echo "Data processed"
""",
        ]
        self.write_script(f"automation_{idx}.sh", random.choice(scripts))
    
    def generate_logging(self, idx):
        scripts = [
            """#!/bin/bash
# Access log analysis
cat /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -20 > /var/log/top_ips.log
echo "Log analysis complete"
""",
            """#!/bin/bash
# Error log aggregation
grep ERROR /var/log/app/*.log > /var/log/daily_errors_$(date +%Y%m%d).log
gzip /var/log/daily_errors_*.log
echo "Errors aggregated"
""",
        ]
        self.write_script(f"logging_{idx}.sh", random.choice(scripts))
    
    def generate_reporting(self, idx):
        scripts = [
            """#!/bin/bash
# Generate usage report
echo "=== System Report $(date) ===" > /tmp/report.txt
df -h >> /tmp/report.txt
free -m >> /tmp/report.txt
uptime >> /tmp/report.txt
mail -s "Daily Report" admin@example.com < /tmp/report.txt
echo "Report sent"
""",
        ]
        self.write_script(f"reporting_{idx}.sh", random.choice(scripts))
    
    def write_script(self, name, content):
        path = self.output_dir / name
        with open(path, 'w') as f:
            f.write(content)
        path.chmod(0o755)

if __name__ == "__main__":
    print("✅ Generating Benign Bash Scripts for Training")
    gen = BenignScriptGenerator()
    gen.generate_all()
