#!/bin/bash
# Simple HTTP server to serve beacon files

cd /opt/c2/implants
# Copy beacons to more generic names
cp $(ls *windows*.exe | head -1) win-beacon.exe
cp $(ls *linux* | grep -v "exe" | head -1) linux-beacon
python3 -m http.server 8080 --bind 127.0.0.1