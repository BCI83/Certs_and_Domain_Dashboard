#!/bin/bash

# Move me to /
# And use me to do a fresh install from Git

cd /cert-monitor
docker compose down -v
cd /
rm -rf /cert-monitor
git clone https://github.com/BCI83/Cets_and_Domain_Dashboard.git /cert-monitor
cd /cert-monitor
docker build --network=host -t cert-monitor/cert-monitor:latest .