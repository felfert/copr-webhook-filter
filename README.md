# copr-webhook-filter
Filtering reverse proxy for github push-webhooks to copr.fedorainfracloud.org

Both COPR and GitHub are not configurable to selectively filter push events by affected paths. This project implements a reverse proxy which can filter by path patterns. This proxy is using WSGI, so it can be deployed in any WSGI-capable server (like `mod_wsgi` for apache). Configuration is done by specifying single yaml file using the env variable "config". The actual configuration of the proxy is documented in the example [copr.yaml](copr.yaml).

On the GitHub side, create a WebHook pointing to your proxy:

 * There are 3 URL query parameters that can be configured
   * `proj` - The project ID on COPR (mandatory)
   * `uuid` - The UUID (access-key) on COPR (mandatory)
   * `pkg`  - The package name to build (optional)

In order to keep the original POST content from GitHub unchanged, these **MUST** be specified in the WebHook URL like in this example:

http://your.proxy.tld/yourHookPath?proj=12345678&uuid=109e265c-a9f2-4e96-a912-1c50bf2ca27c&pkg=mypackage

The project ID and UUID are shown in the Settings page of your COPR project in the `Integrations` tab. The pkg is required only if your project contains multiple packages.
