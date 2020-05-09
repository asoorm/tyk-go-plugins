#!/bin/bash

export VERSION=merge-jwks-0.6
echo $VERSION

git tag ${VERSION}
git push -f --tags
docker build --no-cache -t mangomm/merge-jwks:${VERSION#"merge-jwks-"} --build-arg version=${VERSION} .
docker push mangomm/merge-jwks:${VERSION#"merge-jwks-"}
