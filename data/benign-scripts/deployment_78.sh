#!/bin/bash
# Docker deployment
docker pull myapp:latest
docker stop myapp-container || true
docker rm myapp-container || true
docker run -d --name myapp-container -p 8080:8080 myapp:latest
echo "Container deployed"
