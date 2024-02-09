#!/bin/bash

cd `dirname $0`/cnp
test -x /usr/bin/flake8 && /usr/bin/flake8 --ignore E402,E722,W503,E126,E121,E501 *.py
flake8return=$?
if [ $flake8return -eq 0 ]; then
  echo "flake8 checks successful."
fi
exit $flake8return
