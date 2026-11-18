# A simulated server: sshd (key auth only) + nginx + crond, stress-ng for fault injection.
FROM alpine:3.20
RUN apk add --no-cache openssh nginx stress-ng \
 && adduser -D -s /bin/sh inspector \
 # adduser -D leaves the account locked ('!'); sshd without PAM rejects locked accounts even for keys.
 # '*' = no password login possible, but not locked.
 && sed -i 's/^inspector:!:/inspector:*:/' /etc/shadow \
 && ssh-keygen -A && mkdir -p /run/nginx /data /home/inspector/.ssh
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
