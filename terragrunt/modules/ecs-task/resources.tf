locals {
  datadog_container_cpu     = 64
  datadog_agent_memory      = 768
  datadog_log_router_memory = 256
  requested_task_cpu        = var.cpu + (var.datadog == null ? 0 : 2 * local.datadog_container_cpu)
  requested_task_memory     = var.memory + (var.datadog == null ? 0 : local.datadog_agent_memory + local.datadog_log_router_memory)

  # Linux Fargate sizes, ordered by CPU and then memory. Larger sizes require
  # platform 1.4.0+. https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html
  fargate_sizes = flatten([
    for tier in [
      { cpu = 256, memory = [512, 1024, 2048] },
      { cpu = 512, memory = range(1024, 4097, 1024) },
      { cpu = 1024, memory = range(2048, 8193, 1024) },
      { cpu = 2048, memory = range(4096, 16385, 1024) },
      { cpu = 4096, memory = range(8192, 30721, 1024) },
      { cpu = 8192, memory = range(16384, 61441, 4096) },
      { cpu = 16384, memory = range(32768, 122881, 8192) },
      { cpu = 32768, memory = [61440, 122880, 249856] },
      ] : [for memory in tier.memory : {
        cpu    = tier.cpu
        memory = memory
    }]
  ])
  fitting_task_sizes = [
    for size in local.fargate_sizes : size
    if size.cpu >= local.requested_task_cpu && size.memory >= local.requested_task_memory
  ]

  # Preserve existing task sizes without Datadog. The precondition reports an
  # oversized request rather than failing on an empty list during evaluation.
  task_size = var.datadog == null ? { cpu = var.cpu, memory = var.memory } : try(local.fitting_task_sizes[0], {
    cpu = local.requested_task_cpu, memory = local.requested_task_memory
  })
}
