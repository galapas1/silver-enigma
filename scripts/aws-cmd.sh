# https://dev-clients.cyberight.net/version
aws eks get-token --cluster-name dev-eks-deue29c74 
aws eks --region us-east-2 update-kubeconfig --name dev-eks-deue29c74
kubectl get pods -n deue29c74


kubectl logs -n deue29c74 ninjapanda-66b87fd964-mz7f5 > np-1.log 
kubectl logs -n deue29c74 ninjapanda-66b87fd964-znvxg > np-2.log
