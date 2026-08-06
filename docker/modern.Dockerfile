# Modern sshd, used to validate phase 7 (compatibility with current OpenSSH).
#
# Deliberately keeps the distribution defaults for KexAlgorithms, Ciphers, MACs
# and PubkeyAcceptedAlgorithms. On OpenSSH 8.8+ that means:
#
#   * ssh-rsa (RSA/SHA-1) is NOT accepted, for host keys or for publickey auth;
#     the client must offer rsa-sha2-256 / rsa-sha2-512.
#   * CBC ciphers and hmac-sha1 are off.
#
# The client is therefore expected to FAIL against this image until phase 7 is
# done. That failure is the point: it is the acceptance test for phase 7.
#
# Build context is the repository root:
#   docker build -f docker/modern.Dockerfile -t amphp-ssh-modern .
#   docker run -d -p 2223:22 amphp-ssh-modern

FROM alpine:3.21

RUN apk add --no-cache openssh bash \
    && echo "root:root" | chpasswd

RUN { \
        echo "Port 22"; \
        echo "PermitRootLogin yes"; \
        echo "PasswordAuthentication yes"; \
        echo "PermitUserEnvironment yes"; \
        echo "AcceptEnv FOO"; \
        # Same rationale as the legacy image: no rekeying during the migration.
        echo "RekeyLimit 4G none"; \
    } >> /etc/ssh/sshd_config

RUN ssh-keygen -A

COPY tests/key_ecdsa.pub /tmp/key_ecdsa.pub
COPY tests/key_passphrase_rsa.pub /tmp/key_passphrase_rsa.pub
COPY tests/key_rsa.pub /tmp/key_rsa.pub
COPY tests/key_ed25519.pub /tmp/key_ed25519.pub

RUN mkdir -p /root/.ssh \
    && cat /tmp/key_ecdsa.pub > /root/.ssh/authorized_keys \
    && cat /tmp/key_passphrase_rsa.pub >> /root/.ssh/authorized_keys \
    && cat /tmp/key_rsa.pub >> /root/.ssh/authorized_keys \
    && cat /tmp/key_ed25519.pub >> /root/.ssh/authorized_keys \
    && chmod 700 /root/.ssh \
    && chmod 600 /root/.ssh/authorized_keys

EXPOSE 22

CMD ["/usr/sbin/sshd", "-De"]
