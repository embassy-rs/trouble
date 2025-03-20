#!/bin/bash
set -euo pipefail

mkdir -p ~/.kube
echo "${KUBECONFIG}" > ~/.kube/config
export KUBECONFIG=~/.kube/config
POD=$(kubectl -n embassy get po -l app=website -o jsonpath={.items[0].metadata.name})
kubectl cp crates $POD:/data
kubectl exec $POD -- mkdir -p /usr/share/nginx/html
kubectl cp trouble.tar $POD:/usr/share/nginx/html/
kubectl exec $POD -- find /usr/share/nginx/html
kubectl exec $POD -- tar -C /usr/share/nginx/html -xvf /usr/share/nginx/html/trouble.tar
