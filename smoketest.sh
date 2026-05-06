kubectl create secret generic rig-creds-jbalcas-smoke-esnet-east \
       --namespace=rig \
       --from-literal=token='sO-HKjt2F2ZP8hE3OFOnkuZLSjfciJcqjLWIVOujqto'

kubectl delete job -n rig rig-iri-smoke
kubectl delete pod -n rig rig-iri-smoke

kubectl apply -f smoketest/k8s/iri-smoke-job.yaml
