#!/bin/sh
# Only used on a dedicated builder host, after the previous ECS task stops.
set -e
for id in $(docker ps --quiet); do
  runtime=$(docker inspect --format '{{.HostConfig.Runtime}}' "$id" 2>/dev/null) || continue
  if [ "$runtime" = runsc ]; then
    docker rm --force "$id"
  fi
done
