# K8S chart with Istio service mesh setup

Use the Dockerfile from this folder if you need to run Istio Envoy sidecar. There is a while until Envoy setup iptables and once ready the container will start the app

## Install/ Dry run with Helm2
helm --tiller-namespace <namespace> --dry-run --debug install . --name jwks