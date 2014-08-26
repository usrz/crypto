#!/bin/sh

BASEDIR="`dirname $0`"
if test ! -f "${BASEDIR}/../.classpath.default.txt" ; then
  echo "File \".classpath.default.txt\" not found..."
  exit 1
fi

CLASSPATH="`cat \"${BASEDIR}/../.classpath.default.txt\" | xargs echo | sed 's| |:|g'`"
java -cp "${CLASSPATH}" "org.usrz.libs.crypto.vault.SecureConfigurations" "${@}"
