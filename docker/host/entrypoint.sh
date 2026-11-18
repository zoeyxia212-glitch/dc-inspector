#!/bin/sh
set -e
# Wait for the collector public key produced by the keygen service, then authorise it.
for i in $(seq 1 60); do [ -f /keys/id_ed25519.pub ] && break; sleep 1; done
install -o inspector -g inspector -m 600 /keys/id_ed25519.pub /home/inspector/.ssh/authorized_keys
chown -R inspector:inspector /home/inspector/.ssh && chmod 700 /home/inspector/.ssh
nginx
crond
exec /usr/sbin/sshd -D -e
