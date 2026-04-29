#!/usr/bin/env bash
# Shared configuration for fly machine run commands.

APP="limbic-stargate"
IMAGE="ghcr.io/limbic-systems/codetainer:latest"

COMMON_FLAGS=(
  --app "$APP"
  --region sjc
  --restart no
  --autostart=false
  --vm-memory 4096
  --vm-size shared-cpu-2x
)
