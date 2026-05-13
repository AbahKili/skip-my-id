#!/bin/bash
cd /opt/shortener
export PORT=3097
export DB_PATH=/opt/shortener/data-staging.db
exec node server.js
