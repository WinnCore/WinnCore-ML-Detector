#!/bin/bash
# Application deployment
cd /var/www/app
git pull origin main
npm install
npm run build
pm2 restart app
echo "Deployment complete"
