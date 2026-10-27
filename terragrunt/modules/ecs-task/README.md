# ECS Fargate task

This module creates an ECR repository, Fargate task definition, IAM roles, and a
CloudWatch log group. By default it runs one application container using the
`awslogs` driver. It does not create an ECS service.

## Optional Datadog monitoring

Set `datadog` to delegate task creation to the pinned
`DataDog/ecs-datadog/aws//modules/ecs_fargate` module (version `1.2.2`). It adds
a Datadog Agent and a Fluent Bit FireLens router:

```hcl
datadog = {
  api_key_parameter_arn = "arn:aws:ssm:us-east-1:123456789012:parameter/docs-rs/datadog-api-key"
  environment           = "staging"
}
```

Create the API key as an SSM SecureString before launching tasks. ECS injects it
into the Agent and the FireLens logging configuration; the application container
does not receive it. The execution role receives `ssm:GetParameters` for this
parameter. Upstream's automatic Secrets Manager policy is disabled, and both
existing IAM roles are passed through without extra upstream IAM policies.
Customer-managed KMS keys require a separate `kms:Decrypt` grant.

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
longer copied to CloudWatch. Upstream also sends Agent output through FireLens;
it does not configure log collection for the router's own stdout/stderr. The
CloudWatch group remains for callers without Datadog. Tools reading application
logs from CloudWatch must use Datadog for enabled tasks instead.

Both sidecars are essential containers. The app waits for their `HEALTHY`
conditions, using upstream's health checks. These checks do not guarantee
Datadog intake is reachable. ECS stops the task if an essential container exits.
The app remains essential, so short-lived admin commands still stop the whole
task when they finish. Shutdown timeouts use ECS defaults from the upstream
container definitions.

`cpu` and `memory` describe the **application**, not the entire task. When
Datadog is enabled, the module adds the sidecars internally:

| Container | CPU shares | Memory limit |
| --- | --- | --- |
| Application | `cpu` | `memory` MiB |
| Agent | 64 | 768 MiB by default |
| Log router | 64 | 256 MiB budget by default; see limitation below |

The module selects the smallest supported Linux Fargate CPU tier that fits the
combined CPU and memory, then the smallest supported memory size within that
tier. It rejects requests beyond the supported sizes. For example, an app with
`cpu = 256` and `memory = 1024` needs 384 CPU units and 2048 MiB with default
sidecars, so the task receives 512 CPU units and 2048 MiB. Additional task
headroom does not increase the app's memory limit. Container CPU values are
relative shares, not hard CPU caps; containers can use spare task CPU.

Without Datadog, CPU/memory remain the task values, with no rounding or explicit
container limits added, preserving existing callers. `task_definition.cpu` and
`task_definition.memory` report the resulting **task totals**, so derived tasks
inherit enough resources for all containers.

The site is fixed to `datadoghq.com`. Both sidecars use their default public ECR
repositories with the `latest` tag. Agent memory (768 MiB) and the router memory
budget (256 MiB) are fixed internally. Tasks with 8 or more vCPUs
require Linux Fargate platform 1.4.0 or newer. See the
[AWS size table](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html).

Upstream version `1.2.2` serializes the router memory input as `memory_limit_mib`
instead of ECS's `memory` field. It therefore does not establish a router-specific
hard limit. We include its budget in the task total; the application, Agent,
and overall task limits remain enforced. Verify router memory in staging.
Sidecar resources increase Fargate consumption; Datadog metrics and log ingestion
also affect billing.

Keep the OTLP and FireLens listener ports (4317 and 24224) closed to external
ingress. Containers in the same `awsvpc` task communicate locally; no additional
security-group ingress is required. The task needs outbound HTTPS to the chosen
Datadog site and AWS services.

References: [Fargate integration](https://docs.datadoghq.com/integrations/aws-fargate/),
[Agent OTLP receiver](https://docs.datadoghq.com/opentelemetry/setup/otlp_ingest_in_the_agent/),
[AWS FireLens](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_firelens.html).

## Resource addresses and toggling

Tasks without Datadog retain `aws_ecs_task_definition.task[0]`. A `moved` block
migrates the previous unindexed address without replacing unaffected tasks.
Enabled tasks are owned by
`module.datadog_ecs_fargate_task[0].aws_ecs_task_definition.this`. Enabling or
disabling Datadog changes task-definition ownership and registers a new revision;
ECS services then deploy that revision using their existing rollout settings.
The ECR repository, IAM roles, log group, and service resources remain shared.

The `task_definition` output exposes the common settings needed by derived tasks
such as docs.rs release, independent of which backend creates the definition.

## Tests

Run `terraform init -backend=false` and `terraform test` in this directory. Tests
use a mocked AWS provider and do not provision resources. CI runs them alongside
the OIDC module tests.
