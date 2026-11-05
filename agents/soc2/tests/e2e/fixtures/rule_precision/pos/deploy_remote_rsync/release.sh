#!/bin/sh
set -eu
npm run build
rsync -avz dist/ deploy@prod:/var/www/
