#!/bin/sh
# Configures and starts an sshd for the integration tests inside the current
# container. Used by CI, where running the repository's Dockerfiles as service
# containers would require a registry round trip for no benefit.
#
# Usage: docker/setup-test-sshd.sh [legacy|modern]
#
#   legacy  re-enables the algorithms the client has always supported
#           (ssh-rsa host keys and publickey auth, CBC ciphers, hmac-sha1).
#           Current OpenSSH disables all of them by default.
#   modern  leaves the distribution defaults alone, so ssh-rsa is refused.
#           This is the target for the RSA SHA-2 work.
set -eu

MODE="${1:-legacy}"
PORT="${SSH_LOCAL_PORT:-2222}"

if [ ! -x /usr/sbin/sshd ]; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y -qq openssh-server >/dev/null
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache openssh >/dev/null
    else
        echo "No supported package manager to install openssh-server" >&2
        exit 1
    fi
fi

mkdir -p /run/sshd /root/.ssh
chmod 700 /root/.ssh

echo 'root:root' | chpasswd

# The tests authenticate with these keys. RSA and Ed25519 are expected to work;
# the ECDSA one is there to prove an unsupported format is rejected cleanly.
cat tests/key_rsa.pub tests/key_passphrase_rsa.pub tests/key_ed25519.pub tests/key_ecdsa.pub \
    > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

ssh-keygen -A >/dev/null

cat > /etc/ssh/sshd_config <<EOF
Port ${PORT}
ListenAddress 127.0.0.1
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
PermitUserEnvironment yes
UsePAM no
PrintMotd no

# ProcessTest relies on FOO being accepted and FOO2 being refused.
AcceptEnv FOO

# Set SSH_REKEY_LIMIT to something small (e.g. "1K none") to force the server
# into repeated key re-exchanges during a transfer, which is the only way to
# exercise that path end to end.
RekeyLimit ${SSH_REKEY_LIMIT:-4G none}

LogLevel VERBOSE
EOF

if [ "$MODE" = "legacy" ]; then
    cat >> /etc/ssh/sshd_config <<'EOF'

# Everything below is off by default on current OpenSSH and is restored here so
# the algorithms the client actually implements can still be exercised.
HostKeyAlgorithms +ssh-rsa,ssh-dss
PubkeyAcceptedAlgorithms +ssh-rsa,ssh-dss
CASignatureAlgorithms +ssh-rsa
Ciphers +aes128-cbc,aes192-cbc,aes256-cbc
MACs +hmac-sha1
KexAlgorithms +diffie-hellman-group14-sha1
EOF
fi

/usr/sbin/sshd -f /etc/ssh/sshd_config -E /tmp/sshd.log

# Wait for the port to answer before handing control back.
#
# sshd daemonises here, so it has usually bound the port by the time the
# command returns; the loop only covers a slow start. Probed with whatever is
# present rather than /dev/tcp, which is a bash-ism, or php, which may not be
# on PATH when this runs under sudo.
port_is_open() {
    if command -v nc >/dev/null 2>&1; then
        nc -z 127.0.0.1 "${PORT}" >/dev/null 2>&1
        return $?
    fi

    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -q ":${PORT}[[:space:]]"
        return $?
    fi

    # Nothing to probe with; assume the daemon came up.
    return 0
}

i=0
while [ "$i" -lt 30 ]; do
    if port_is_open; then
        echo "sshd (${MODE}) is listening on 127.0.0.1:${PORT}"
        exit 0
    fi
    i=$((i + 1))
    sleep 1
done

echo "sshd did not come up on port ${PORT}" >&2
cat /tmp/sshd.log >&2 || true
exit 1
