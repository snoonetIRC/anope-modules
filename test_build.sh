#!/usr/bin/env bash

set -e

if [[ -z $ANOPE_VERSION ]]; then
    ANOPE_VERSION="2.0.9"
fi

wget -O anope.tar.gz "https://github.com/anope/anope/archive/${ANOPE_VERSION}.tar.gz"

tar xvf anope.tar.gz

SRC_DIR="anope-${ANOPE_VERSION}"

cp -r modules/* $SRC_DIR/modules/third/

cd $SRC_DIR

cat > config.cache << EOF
INSTDIR="$(pwd)/run"
RUNGROUP=""
UMASK=077
DEBUG="yes"
USE_PCH="no"
EXTRA_INCLUDE_DIRS=""
EXTRA_LIB_DIRS=""
EXTRA_CONFIG_ARGS=""
EOF

./Config -quick -nointro && pushd build && make --jobs $(nproc) install
exit $?
