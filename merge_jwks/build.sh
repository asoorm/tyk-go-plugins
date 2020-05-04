#!/bin/bash

docker build -t mangomm/merge-jwks:0.1 --build-arg version="feature/merge-jwks" .
#docker push mangomm/merge-jwks:0.1
