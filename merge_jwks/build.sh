#!/bin/bash

docker build --no-cache -t mangomm/merge-jwks:0.5 --build-arg version="merge-jwks-0.5" .
docker push mangomm/merge-jwks:0.5
