# appsec
This repo contains utility to pull AppSec data from Dynatrace using REST API.
In order to use this utility, you would need 2 items:
Name | Description
------------ | -------------
Dynatrace tenant url | `Managed` https://{your-domain}/e/{your-environment-id}  <br/>`SaaS` https://{your-environment-id}.live.dynatrace.com
API Token | You need the Write configuration (WriteConfig) permission assigned to your API token  

The API Token needs to have these minimum permissions:
#### API v2
* Read Entities
* Read Security Problems

#### API v1
* Access Problem and event feed, metrics and topology

You can [download](https://github.com/dynatrace-oss/PTC-Windchill/releases/latest) the utility for you OS here.
