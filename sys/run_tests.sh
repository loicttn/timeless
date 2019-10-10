#!/bin/bash

if [ "$OSTYPE" != "linux-gnu" ] && [ "$OSTYPE" != "darwin"* ]; then
    echo "Only supports Linux and MacOSx."
    exit 1
fi
pipenv install --dev
pipenv run pytest tests/unit/*