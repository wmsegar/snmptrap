# dynatracesnmp

## Usage

Run the main binary by providing the following parameters:

```
-api-base-url Dynatrace base URL, Saas: https://<TENANT>.live.dynatrace.com Managed: https://{your-domain}/e/{your-environment-id}
-api-token Dynatrace API Token with permissions to query Problems
-listen The port that the SNMP listener should listen on
-target The hostname:port where the SNMP server is listening
```

Sample:
```
./main -api-base-url https://<DT_MANAGED_URL>/e/<environmentID> -api-token <API-TOKEN> -listen 9000 -target localhost:9021
```