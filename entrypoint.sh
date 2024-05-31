#!/bin/sh
set -e
echo remote ${APP_GRE_REMOTE_IP} local ${APP_GRE_LOCAL_IP}
if [ -n "${APP_GRE_LOCAL_IP}" ]; then
    ip link add gt0 type gretap remote ${APP_GRE_REMOTE_IP} local ${APP_GRE_LOCAL_IP}
else
    ip link add gt0 type gretap remote ${APP_GRE_REMOTE_IP}
fi
ip link set gt0 up
# ip link add gt0.810 link gt0 type vlan id 810
# ip link set gt0.810 up
# ip addr add 192.0.2.1/32 dev gt0.810
ip addr add 192.0.2.1/32 dev gt0

exec "$@"