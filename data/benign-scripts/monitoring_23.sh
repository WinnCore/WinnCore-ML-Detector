#!/bin/bash
# Service monitoring
systemctl status nginx > /dev/null || systemctl restart nginx
systemctl status postgresql > /dev/null || systemctl restart postgresql
echo "Services checked"
