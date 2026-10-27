# ECS Fargate task

This module creates an ECR repository, Fargate task definition, IAM roles, and a
CloudWatch log group. By default it runs one application container using the
`awslogs` driver. It does not create an ECS service.

## Optional Datadog monitoring

Set `datadog` to add a Datadog Agent and a Fluent Bit FireLens router:

```hcl
datadog = {
  api_key_parameter_arn = "arn:aws:ssm:us-east-1:123456789012:parameter/docs-rs/datadog-api-key"
  environment           = "staging"
  site                  = "datadoghq.com"
}
```

Create the API key as an SSM SecureString before launching tasks. ECS injects it
into the Agent and the FireLens logging configuration; the application container
does not receive it. The execution role receives `ssm:GetParameters` for this
parameter. Customer-managed KMS keys require a separate `kms:Decrypt` grant.

The Agent uses the Fargate task metadata endpoint to collect container CPU,
memory, and disk I/O metrics, and task-level ephemeral-storage usage/capacity.
This is task storage visibility, not access to the underlying Fargate host's
filesystems. Use Fargate platform 1.4.0 or later for ephemeral-storage metrics.
No `DD_HOSTNAME` is set.

The Agent's built-in OTLP receiver is the local collector, listening on gRPC port
4317. The module sets `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317`,
`OTEL_SERVICE_NAME` to the task family, and appends an environment resource
attribute on the application. This overrides the endpoint and service name while
preserving other configured `OTEL_RESOURCE_ATTRIBUTES`.
Existing OpenTelemetry instrumentation must export to this endpoint; installing
the Agent does not add instrumentation to the app. The default setup does not
include a separate OpenTelemetry Collector or automatically instrument APM.

Application stdout/stderr uses `awsfirelens` and is sent directly to Datadog over
TLS, with ECS metadata and service/environment tags. The router parses serialized
JSON logs. App-specific fields may still need Datadog message/status remappers
(for example Rust tracing's nested `fields.message`). Application logs are no
longer copied to CloudWatch. The Agent and router diagnostic logs continue using
the module's `/ecs/<task family>` group. Tools reading application logs from
CloudWatch must use Datadog for enabled tasks instead.

Both sidecars are essential containers. The app waits for their `START` conditions;
this guarantees startup order, not that Datadog intake is reachable. ECS stops the
task if an essential container exits. The app remains essential, so short-lived
admin commands still stop the whole task when they finish. Sidecars have 60-second
stop timeouts to allow shutdown and log flushing.

Task CPU/memory values are totals for all containers. The defaults allocate:

| Container | CPU shares | Memory limit |
| --- | --- | --- |
| Agent | 64 | 768 MiB |
| Log router | 64 | 256 MiB |
| Application | Task CPU minus 128 | Task memory minus 1024 MiB |

Increase the task budget before enabling Datadog. The module rejects budgets
that leave no resources for the app. Agent/router memory limits and image
references are configurable; the defaults track the Agent's `7` and Fluent Bit's
`stable` tags. Override them with immutable versions/digests for pinned rollouts.
Sidecar resources increase Fargate consumption; Datadog metrics and log ingestion
also affect billing.

Keep the OTLP and FireLens listener ports (4317 and 24224) closed to external
ingress. Containers in the same `awsvpc` task communicate locally; no additional
security-group ingress is required. The task needs outbound HTTPS to the chosen
Datadog site and AWS services.

References: [Fargate integration](https://docs.datadoghq.com/integrations/aws-fargate/),
[Agent OTLP receiver](https://docs.datadoghq.com/opentelemetry/setup/otlp_ingest_in_the_agent/),
[AWS FireLens](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_firelens.html).

## Tests

Run `terraform init -backend=false` and `terraform test` in this directory. Tests
use a mocked AWS provider and do not provision resources. CI runs them alongside
the OIDC module tests.
