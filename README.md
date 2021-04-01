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

You can [download](https://github.com/Dynatrace-Asad-Ali/appsec/releases/latest) the utility for you OS here. Unzip the zip file before running the utility.

### Usage
To run the utility run the following command
appsec_<version> -url <Dynatrace tenant url including https://> -token <token>
This will generate output where the data is grouped by vulnerable library and for each library it will list the process names that are using it.
The utility also allows you to group the data by process name instead of vulnerable library. To get the data grouped by process name, run the following command
appsec_<version> -url <Dynatrace tenant url including https://> -token <token> -groupByProcess

The utility also allow you to pass the Dynatrace url and the token as an environment variable instead of providing these values at command line. To use the environment variables instead, please set these 2 environment variables before running the command:
* DT_URL
* DT_TOKEN

If you provide environment variables and also provide the "-url" and "-token" at the command line, the environment varialbe will take precedence. You can also mix and match the environment variable and the command line argument. For example, you can provide "-url" to the command line and provide token as an environment variable.
