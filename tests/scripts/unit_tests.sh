#! /bin/bash
if [ -f .coverage ]; then
  rm .coverage
fi

python3 -m nose tests/unit \
--with-coverage \
--cover-package=resources/remediator \
--cover-package=resources/event_translator \
--cover-package=resources/poller \
--cover-min-percentage=65 \
--cover-html \
--cover-html-dir=htmlcov