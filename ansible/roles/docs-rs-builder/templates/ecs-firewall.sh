#!/bin/bash
# {{ ansible_managed }}
# common's INPUT policy otherwise rejects Docker bridge requests redirected
# by ECS-Init to the local task-credential proxy.
cmd4 -A input_pre -i docker0 -p tcp --dport 51679 -j ACCEPT
