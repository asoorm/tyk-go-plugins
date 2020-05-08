#!/bin/bash

export VERSION=merge-jwks-0.5
echo $VERSION

git tag ${VERSION}
git push -f --tags
docker build --no-cache -t mangomm/${VERSION} --build-arg version=${VERSION} .
#docker push mangomm/${VERSION}
