# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""TLS Management Service Layer."""


import os
import subprocess
from typing import NamedTuple


def _get_autocert_cn(autocert_conf_dir="/etc/autocert/postfix"):
    # autocert relation is reversed so we can't get this info from
    # juju relations but rather try work it out from the shipped out
    # config.
    if os.path.exists(autocert_conf_dir):
        for f in sorted(os.listdir(autocert_conf_dir)):
            if not f.endswith(".ini"):
                continue
            return f[:-4]
    return ""


class TLSConfigPaths(NamedTuple):
    """A container for TLS file paths.

    Attributes:
        tls_dh_params: Path to the Diffie-Hellman parameters file.
        tls_cert: Path to the TLS certificate file.
        tls_key: Path to the TLS private key file.
        tls_cert_key: Path to a combined certificate and key file (currently unused).
    """
    tls_dh_params: str
    tls_cert: str
    tls_key: str
    tls_cert_key: str


def get_tls_config_paths(tls_dh_params: str) -> TLSConfigPaths:
    tls_cert_key = ""
    tls_cert = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
    tls_key = "/etc/ssl/private/ssl-cert-snakeoil.key"
    tls_cn = _get_autocert_cn()
    if tls_cn:
        # autocert currently bundles certs with the key at the end which postfix doesn't like:
        # `warning: error loading chain from /etc/postfix/ssl/{...}.pem: key not first`
        # Let's not use the newer `smtpd_tls_chain_files` postfix config for now.
        # tls_cert_key = f"/etc/postfix/ssl/{tls_cn}.pem"
        tls_cert = f"/etc/postfix/ssl/{tls_cn}.crt"
        tls_key = f"/etc/postfix/ssl/{tls_cn}.key"
        tls_dh_params = "/etc/postfix/ssl/dhparams.pem"
    if not os.path.exists(tls_dh_params):
        subprocess.call(["openssl", "dhparam", "-out", tls_dh_params, "2048"])  # nosec

    return TLSConfigPaths(
        tls_dh_params=tls_dh_params,
        tls_cert=tls_cert,
        tls_key=tls_key,
        tls_cert_key=tls_cert_key,
    )
