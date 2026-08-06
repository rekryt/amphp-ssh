# Legacy sshd for regression testing against the algorithms the client has
# always supported: CBC ciphers, hmac-sha1, ssh-rsa (SHA-1) host keys.
#
# Kept on Alpine 3.6 on purpose. A modern OpenSSH disables all of the above by
# default, so this image is the only place those code paths are still exercised.
# See docker/modern.Dockerfile for the forward-looking counterpart.
#
# Build context is the repository root:
#   docker build -f docker/legacy.Dockerfile -t amphp-ssh-legacy .
#   docker run -d -p 2222:22 amphp-ssh-legacy

FROM alpine:3.6

RUN apk --update add --no-cache openssh bash \
    && sed -i s/#PermitRootLogin.*/PermitRootLogin\ yes/ /etc/ssh/sshd_config \
    && echo "root:root" | chpasswd

RUN sed -ie 's/#Port 22/Port 22/g' /etc/ssh/sshd_config
RUN sed -ie 's/#PermitUserEnvironment no/PermitUserEnvironment yes/g' /etc/ssh/sshd_config
RUN echo "AcceptEnv FOO" >> /etc/ssh/sshd_config
RUN sed -ri 's/#HostKey \/etc\/ssh\/ssh_host_key/HostKey \/etc\/ssh\/ssh_host_key/g' /etc/ssh/sshd_config
RUN sed -ir 's/#HostKey \/etc\/ssh\/ssh_host_rsa_key/HostKey \/etc\/ssh\/ssh_host_rsa_key/g' /etc/ssh/sshd_config
RUN sed -ir 's/#HostKey \/etc\/ssh\/ssh_host_dsa_key/HostKey \/etc\/ssh\/ssh_host_dsa_key/g' /etc/ssh/sshd_config
RUN sed -ir 's/#HostKey \/etc\/ssh\/ssh_host_ecdsa_key/HostKey \/etc\/ssh\/ssh_host_ecdsa_key/g' /etc/ssh/sshd_config
RUN sed -ir 's/#HostKey \/etc\/ssh\/ssh_host_ed25519_key/HostKey \/etc\/ssh\/ssh_host_ed25519_key/g' /etc/ssh/sshd_config
RUN echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc" >> /etc/ssh/sshd_config

# Keep rekeying out of the picture while the v3 migration is in progress: an
# unhandled mid-session KEXINIT currently looks like an unexplained disconnect
# and would be misread as a migration regression. Restore the default and add a
# dedicated low-limit image once rekeying is actually implemented.
RUN echo "RekeyLimit 4G none" >> /etc/ssh/sshd_config

# RUN echo "LogLevel DEBUG3" >> /etc/ssh/sshd_config

RUN /usr/bin/ssh-keygen -A
RUN ssh-keygen -t rsa -b 4096 -f  /etc/ssh/ssh_host_key

COPY tests/key_ecdsa.pub /tmp/key_ecdsa.pub
COPY tests/key_passphrase_rsa.pub /tmp/key_passphrase_rsa.pub
COPY tests/key_rsa.pub /tmp/key_rsa.pub
COPY tests/key_ed25519.pub /tmp/key_ed25519.pub

RUN mkdir /root/.ssh \
    && cat /tmp/key_ecdsa.pub > /root/.ssh/authorized_keys \
    && cat /tmp/key_passphrase_rsa.pub >> /root/.ssh/authorized_keys \
    && cat /tmp/key_rsa.pub >> /root/.ssh/authorized_keys \
    && cat /tmp/key_ed25519.pub >> /root/.ssh/authorized_keys

EXPOSE 22

CMD ["/usr/sbin/sshd","-De"]
