# copr-webhook-filter
Filtering reverse proxy for github push-webhooks to copr.fedorainfracloud.org

Both COPR and GitHub are not configurable to selectively filter push events
by affected paths. This project implements a reverse proxy which can filter
by path patterns. This proxy is using WSGI, so it can be deployed in any
WSGI-capable server (like `mod_wsgi` for apache). Configuration is done by
specifying single yaml file using the env variable "config". The actual
configuration is documented in the example [copr.yaml](copr.yaml).
