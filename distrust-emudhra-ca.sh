#!/bin/sh
mode=${1:-check}
hosts="dv-g3b-emudhra dv-g3b-aaa-emudhra"
comodo='Comodo AAA Services root'
emsign='emSign ECC Root CA - G3'

die() {
  echo "$0: $1" >&2
  exit "${2:-1}"
}

run() { "$@" || die "failed ($?): $*"; }

pkcs11() { echo "pkcs11:object=$(echo "$1" | sed 's/ /%20/g');type=cert"; }

sedi() {
  f=$1
  shift
  sed "$@" "$f" >"$f.new" && cat "$f.new" >"$f" && rm "$f.new"
}

detect() {
  case "$(uname -s)" in
  Darwin)
    echo macos
    return
    ;;
  FreeBSD)
    echo freebsd
    return
    ;;
  NetBSD)
    echo netbsd
    return
    ;;
  esac
  [ -r /etc/os-release ] || {
    echo unknown
    return
  }
  . /etc/os-release
  case "$ID ${ID_LIKE:-}" in
  *debian* | *ubuntu*) echo debian ;;
  *alpine* | *wolfi*) echo alpine ;;
  *fedora* | *rhel* | *centos* | *amzn*) echo fedora ;;
  *suse*) echo suse ;;
  *arch*) echo arch ;;
  *nixos*) echo nixos ;;
  *) echo unknown ;;
  esac
}

# 0 = all blocked, 1 = something still trusted, 2 = could not verify
check() {
  command -v curl >/dev/null || die "no curl; cannot verify" 2
  trusted=0 unreachable=0
  for h in $hosts; do
    err=$(curl -sS -o /dev/null --max-time 10 "https://$h.we-have-a-problem.com/" 2>&1) && rc=0 || rc=$?
    case $rc in
    0)
      echo "STILL TRUSTED  $h"
      trusted=1
      ;;
    60) echo "blocked        $h" ;;
    *)
      echo "unreachable    $h  (curl $rc: $(echo "$err" | head -n 1))" >&2
      unreachable=1
      ;;
    esac
  done
  if [ $trusted -eq 0 ] && [ $unreachable -eq 0 ]; then
    echo "OK: both test hosts rejected"
  elif [ $trusted -ne 0 ]; then
    echo "ACTION NEEDED: run  sudo sh $0 apply"
  fi
  [ $trusted -eq 0 ] || return 1
  [ $unreachable -eq 0 ] || return 2
}

p11_block() {
  run trust extract --overwrite --format=pem-bundle \
    --filter="$(pkcs11 "$comodo")" "$1/Comodo_AAA_Services_root.pem"
  run trust extract --overwrite --format=pem-bundle \
    --filter="$(pkcs11 "$emsign")" "$1/emSign_ECC_Root_CA_-_G3.pem"
}

apply() {
  case "$1" in
  macos)
    [ -f /etc/ssl/cert.pem.bak ] || run cp /etc/ssl/cert.pem /etc/ssl/cert.pem.bak
    run awk '/^(###|===) /{skip=0}
           /^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1}
           !skip' /etc/ssl/cert.pem.bak >/etc/ssl/cert.pem
    for n in "$emsign" "AAA Certificate Services"; do
      security find-certificate -p -c "$n" /System/Library/Keychains/SystemRootCertificates.keychain >"/tmp/$$.pem" 2>/dev/null &&
        run security add-trusted-cert -d -r deny -k /Library/Keychains/System.keychain "/tmp/$$.pem"
    done
    rm -f "/tmp/$$.pem"
    ;;
  debian)
    run sedi /etc/ca-certificates.conf -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \
      -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|'
    run update-ca-certificates
    ;;
  alpine)
    if command -v apk >/dev/null; then run apk add -q ca-certificates; fi
    run sedi /etc/ca-certificates.conf -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|'
    run update-ca-certificates
    ;;
  fedora)
    d=/etc/pki/ca-trust/source/blocklist
    [ -d $d ] || d=/etc/pki/ca-trust/source/blacklist
    p11_block $d
    run update-ca-trust
    ;;
  suse)
    d=/etc/pki/trust/blocklist
    [ -d $d ] || d=/etc/pki/trust/blacklist
    p11_block $d
    run update-ca-certificates
    ;;
  arch)
    run trust extract --overwrite --format=pem-bundle \
      --filter="$(pkcs11 "$emsign")" /etc/ca-certificates/trust-source/blocklist/emSign_ECC_Root_CA_-_G3.pem
    run update-ca-trust
    ;;
  freebsd)
    run cp /etc/ssl/certs/14bc7599.0 /usr/share/certs/untrusted/14bc7599.pem
    run cp /etc/ssl/certs/ee64a828.0 /usr/share/certs/untrusted/ee64a828.pem
    run certctl rehash
    ;;
  netbsd)
    run certctl untrust /usr/share/certs/mozilla/all/emSign_ECC_Root_CA_-_G3.pem
    run certctl untrust /usr/share/certs/mozilla/all/Comodo_AAA_Services_root.pem
    ;;
  nixos)
    echo 'Add to configuration.nix:'
    echo '  security.pki.caCertificateBlacklist = [ "Comodo AAA Services root" "emSign ECC Root CA - G3" ];'
    exit 1
    ;;
  *)
    die "unsupported platform; see https://emudhra.we-have-a-problem.com/"
    ;;
  esac
}

platform=$(detect)
echo "platform: $platform"
case $mode in
check) check ;;
apply)
  [ "$(id -u)" = 0 ] || die "apply needs root: sudo sh $0 apply"
  apply "$platform"
  echo "applied; verifying:"
  check || die "still trusted or unverifiable after apply; see https://emudhra.we-have-a-problem.com/"
  ;;
-h | --help | help) echo "usage: $0 [check|apply]" ;;
*) die "usage: $0 [check|apply]" 2 ;;
esac
