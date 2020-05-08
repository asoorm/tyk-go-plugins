FROM golang:1.13.1-alpine as build

ARG version

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN apk update && apk upgrade && \
    apk add --no-cache bash git openssh && \
    mkdir -p /go/src/github.com/asoorm && \
    cd /go/src/github.com/asoorm && ls -al && \
    git clone https://github.com/asoorm/tyk-go-plugins.git && \
    ls -al && \
    pwd && \
    cd tyk-go-plugins && ls -al

RUN cd /go/src/github.com/asoorm/tyk-go-plugins && \
    git checkout --force $version && \
    export GIT_COMMIT=$(git rev-list -1 HEAD) && \
    echo "commit: $GIT_COMMIT" && \
    export GIT_TAG=$(git tag) && \
    echo "tag: $GIT_TAG" && \
    cd merge_jwks && go install -ldflags "-X main.GitCommit=$GIT_COMMIT -X main.GitTag=$GIT_TAG" -a -i -ldflags="-s -w" .

FROM alpine:3.11
RUN apk --no-cache add ca-certificates && \
    adduser -D -g merge_jwks merge_jwks
USER merge_jwks
WORKDIR /opt/merge_jwks
COPY --from=build /go/bin/merge_jwks /opt/merge_jwks/merge_jwks
COPY config.yaml /opt/merge_jwks/config.yaml
USER merge_jwks

EXPOSE 9000

CMD ["./merge_jwks"]
