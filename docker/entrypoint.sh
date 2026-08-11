#!/bin/sh
set -e

echo "Waiting for database to be ready..."
until npx prisma migrate deploy 2>/dev/null; do
  echo "Database not ready yet, retrying in 2s..."
  sleep 2
done

echo "Migrations applied. Starting server..."
node src/app.js
