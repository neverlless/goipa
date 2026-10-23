#!/usr/bin/env bash
# Start (or stop) a disposable FreeIPA container and configure this Linux host
# to talk to it, so `go test -tags integration ./...` works. Needs docker and sudo.
set -euo pipefail

IMAGE="${IMAGE:-almalinux-9-4.13.4}"
IPA_FQDN="${IPA_FQDN:-ipa.example.test}"
IPA_REALM="${IPA_REALM:-EXAMPLE.TEST}"
ENV_FILE="${ENV_FILE:-.env}"
NAME=goipa-ipa

# Refuse to clobber a host enrolled in another IPA unless on a CI runner or FORCE=1.
guard() {
  if [ -n "${GITHUB_ACTIONS:-}" ] || [ "${FORCE:-}" = 1 ]; then return; fi
  if [ -e /etc/ipa/default.conf ] && ! grep -qF "$IPA_FQDN" /etc/ipa/default.conf; then
    echo "/etc/ipa/default.conf belongs to another IPA server; this script would overwrite it" >&2
    echo "and /etc/ipa/ca.crt, /etc/krb5.conf and your Kerberos ccache. Rerun with FORCE=1 to proceed." >&2
    exit 1
  fi
}

up() {
  local pw keytab
  guard
  pw=$(openssl rand -hex 16)
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::add-mask::$pw"; fi

  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" -h "$IPA_FQDN" \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -p 443:443 -p 88:88/tcp -p 88:88/udp \
    -e PASSWORD="$pw" \
    "quay.io/freeipa/freeipa-server:$IMAGE" \
    -U -r "$IPA_REALM" --no-ntp --no-ui-redirect --skip-mem-check >/dev/null

  local ready=0 i
  for i in $(seq 1 90); do
    if docker exec "$NAME" sh -c 'echo "$PASSWORD" | kinit admin >/dev/null && ipa ping' >/dev/null 2>&1; then
      ready=1
      break
    fi
    [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" = true ] || break
    sleep 10
  done
  if [ "$ready" -ne 1 ]; then
    docker logs --tail 100 "$NAME" >&2
    echo "FreeIPA did not become ready" >&2
    exit 1
  fi

  grep -q "[[:space:]]$IPA_FQDN\$" /etc/hosts || echo "127.0.0.1 $IPA_FQDN" | sudo tee -a /etc/hosts >/dev/null
  sudo mkdir -p /etc/ipa
  docker exec "$NAME" cat /etc/ipa/ca.crt | sudo tee /etc/ipa/ca.crt >/dev/null
  printf '[global]\nxmlrpc_uri = https://%s/ipa/xml\nrealm = %s\n' "$IPA_FQDN" "$IPA_REALM" | sudo tee /etc/ipa/default.conf >/dev/null
  if [ -e /etc/krb5.conf ] && [ ! -e /etc/krb5.conf.goipa-bak ]; then
    sudo cp -p /etc/krb5.conf /etc/krb5.conf.goipa-bak
  fi
  # forwardable as ipa-client-install sets it: FreeIPA's S4U2Proxy needs a
  # forwardable service ticket, else every call fails 2100 "Credential cache is empty".
  printf '[libdefaults]\n default_realm = %s\n forwardable = true\n[realms]\n %s = {\n  kdc = %s\n }\n' "$IPA_REALM" "$IPA_REALM" "$IPA_FQDN" | sudo tee /etc/krb5.conf >/dev/null

  # Dedicated user: ipa-getkeytab rotates keys, which would break admin password tests.
  docker exec "$NAME" sh -c 'echo "$PASSWORD" | kinit admin >/dev/null && ipa user-add goipa-svc --first Go --last Svc >/dev/null && ipa-getkeytab -p goipa-svc -k /tmp/svc.keytab >/dev/null'
  keytab="${RUNNER_TEMP:-$PWD}/svc.keytab"
  docker cp "$NAME:/tmp/svc.keytab" "$keytab"
  chmod 600 "$keytab"

  # The ccache tests read /tmp/krb5cc_<uid>.
  if command -v kinit >/dev/null 2>&1; then
    echo "$pw" | kinit "admin@$IPA_REALM"
  fi

  (
    umask 077
    printf 'IPA_ADMIN_USER=admin\nIPA_ADMIN_PASS=%s\nIPA_KEYTAB=%s\nIPA_KEYTAB_USER=goipa-svc\n' "$pw" "$keytab" >"$ENV_FILE"
  )
  chmod 600 "$ENV_FILE"
  echo "FreeIPA is up; credentials written to $ENV_FILE"
}

case "${1:-up}" in
  up) up ;;
  down) docker rm -f "$NAME" ;;
  *) echo "usage: $0 [up|down]" >&2; exit 2 ;;
esac
