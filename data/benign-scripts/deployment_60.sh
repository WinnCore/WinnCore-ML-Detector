#!/bin/bash
# Static site deployment
cd /var/www/site
git pull
bundle install
jekyll build
systemctl reload nginx
echo "Site deployed"
