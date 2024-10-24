#!/bin/bash

# Move this to /
# And use it to do a fresh install from Git

cd /cert-monitor
docker compose down -v
cd /
docker rmi $(docker images cert-monitor/cert-monitor:latest -q)
docker network prune -f
rm -rf /cert-monitor
git clone https://github.com/BCI83/Certs_and_Domain_Dashboard.git /cert-monitor
cp -r /expiry_certs /cert-monitor/ssl_cert
cd /cert-monitor
docker build --network=host -t cert-monitor/cert-monitor:latest .


# useful commands
# docker exec -it cert-monitor-db-1 psql -U certmonitoruser -d certmonitor
# select * from domain;
# select * from subdomain;
# delete from domain where {column} = 'value';
