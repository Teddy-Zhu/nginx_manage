#!/bin/sh
set -eu
cd "${NGINXPANEL_SOFTWARE_DIR:?missing application directory}"
cp .package/manage.sh ./manage.sh
if [ ! -f compose.yaml ]; then cp .package/compose.yaml ./compose.yaml; fi
if [ ! -d data ]; then
  cp -R .package/data ./data
  chmod 755 data
  chmod 644 data/index.html
fi
/bin/sh ./manage.sh install
