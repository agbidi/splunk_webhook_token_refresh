# Splunk Observability Cloud webhook token refresher

This scheduled Python job gets an OAuth access token, updates the `Authorization` header on an existing Splunk Observability Cloud webhook integration, and publishes a gauge metric for the run.

It uses only the Python standard library.

## Configure

Copy `config.example.json` to `config.json`, then set:

- `oauth.token_url`, `client_id`, `scope`, and any provider-specific parameters such as `audience`.
- `oauth.client_secret_env` to the name of an environment variable containing the OAuth client secret.
- `oauth.client_auth_method` to `client_secret_post` (default) or `client_secret_basic`, as required by the OAuth provider.
- Optionally set `oauth.accept` only if the OAuth provider requires a specific `Accept` header. It is omitted by default; this matches the documented AppDynamics Controller token request.
- `splunk.realm` and `splunk.integration_id` for the target organization and saved Webhook integration.
- `splunk.api_token_env` to the name of an environment variable containing a Splunk token authorized to update integrations.
- `monitoring.ingest_token_env` to the name of an environment variable containing a Splunk ingest token. The metric is sent to the organization's ingest endpoint.

The script updates only the `Authorization` header, preserving the other headers and the rest of the integration object returned by the API. Keep `config.json` and the environment variables out of source control, and restrict access to them.

Put the secret values in a `.env` file in this directory. The script uses only the Python standard library and does not load `.env` automatically; source it in the shell before running the script:

```sh
OAUTH_CLIENT_SECRET='replace-with-oauth-client-secret'
SPLUNK_INTEGRATIONS_API_TOKEN='replace-with-splunk-integration-api-token'
SPLUNK_METRIC_INGEST_TOKEN='replace-with-splunk-ingest-token'
```

## Run

```sh
source .env
python3 refresh_webhook_token.py --config config.json
```

Add `--debug` to print request metadata, a bounded request-payload preview, and a bounded excerpt of HTTP error responses when troubleshooting. The diagnostic output omits URL query strings and redacts common credential fields such as authorization headers, tokens, secrets, passwords, API keys, and cookies.

The process exits `0` only when OAuth token retrieval, the integration update, and status metric publication all succeed. It exits nonzero if the refresh fails. After a successful config load, it attempts to publish the status gauge on every run:

- `1`: OAuth token retrieval and integration update succeeded.
- `0`: either refresh step failed.

If publishing the metric itself fails, the job logs the failure and exits nonzero; Splunk receives no datapoint for that run. Consider alerting both on a reported zero and on missing datapoints.

Default metric name: `splunk.webhook.oauth_token_refresh.success`. The metric is sent as a gauge to `https://ingest.<realm>.observability.splunkcloud.com/v2/datapoint` with the configured dimensions and an `integration_id` dimension.

## Schedule

Run at an interval shorter than the downstream OAuth token lifetime, with enough margin for delays or transient failures. Each invocation obtains a new token rather than relying on a local token cache.
