#!/bin/bash

docker build --no-cache -t mangomm/merge-jwks:0.4 --build-arg version="feature/merge-jwks" .
docker push mangomm/merge-jwks:0.4
