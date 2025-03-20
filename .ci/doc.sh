#!/bin/bash
set -euo pipefail

mkdir -p ~/.kube
echo "${KUBECONFIG}" > ~/.kube/config
export KUBECONFIG=~/.kube/config
POD=$(kubectl -n embassy get po -l app=docserver -o jsonpath={.items[0].metadata.name})
kubectl cp crates $POD:/data
