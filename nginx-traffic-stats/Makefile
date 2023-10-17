docker:
	docker build -t ghcr.io/nousefreak/pocs/nginx-traffic-stats:dev .
	docker push ghcr.io/nousefreak/pocs/nginx-traffic-stats:dev

tunnel:
	open http://0.0.0.0:2112/metrics
	kubectl port-forward $$(kubectl get pod -n ingress-nginx -l app=nginx-traffic-stats -oname) 2112

logs:
	kubectl logs -f $$(kubectl get pod -n ingress-nginx -l app=nginx-traffic-stats -oname)
	