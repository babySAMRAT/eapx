"""
cert_wizard.py — Generate fake CA + server certificates for the
rogue RADIUS server. Supports cloned cert metadata from cert_clone.py
to mirror the real AP's certificate fields (CN, O, OU, SAN).
"""

import subprocess
import os
import json
import datetime


def generate_certs(cn="FakeRADIUS", org="Corp", country="IN",
                   ou=None, san=None, issuer_cn=None, issuer_org=None):
    """
    Generate CA + server certificates. When cloned metadata is provided,
    the certificates will mirror the real RADIUS server's fields.

    Args:
        cn:         Common Name for server cert
        org:        Organization
        country:    Country code
        ou:         Organizational Unit (optional)
        san:        List of SAN DNS names (optional)
        issuer_cn:  CA Common Name (mirrors real CA if cloned)
        issuer_org: CA Organization
    """

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cert_dir = os.path.join(base_dir, "certs")
    os.makedirs(cert_dir, exist_ok=True)

    # Build CA subject
    ca_cn  = issuer_cn  or f"{cn}-CA"
    ca_org = issuer_org or org

    ca_subj = f"/C={country}/O={ca_org}/CN={ca_cn}"
    srv_subj = f"/C={country}/O={org}"
    if ou:
        srv_subj += f"/OU={ou}"
    srv_subj += f"/CN={cn}"

    print("[*] Generating CA certificate...")
    print(f"    Subject: {ca_subj}")
    subprocess.run([
        "openssl", "req", "-new", "-x509", "-nodes",
        "-keyout", f"{cert_dir}/ca.key",
        "-out",    f"{cert_dir}/ca.pem",
        "-days",   "3650",
        "-subj",   ca_subj,
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("[*] Generating server key and CSR...")
    print(f"    Subject: {srv_subj}")

    csr_cmd = [
        "openssl", "req", "-new", "-nodes",
        "-keyout", f"{cert_dir}/server.key",
        "-out",    f"{cert_dir}/server.csr",
        "-subj",   srv_subj,
    ]

    # Add SAN extension to the CSR if provided
    san_ext_file = None
    if san:
        san_str = ",".join(f"DNS:{s}" for s in san)
        san_ext_file = "/tmp/eapx_san.cnf"
        with open(san_ext_file, "w") as f:
            f.write(f"[req]\n")
            f.write(f"distinguished_name = req_dn\n")
            f.write(f"req_extensions = v3_req\n\n")
            f.write(f"[req_dn]\n\n")
            f.write(f"[v3_req]\n")
            f.write(f"subjectAltName = {san_str}\n")
        csr_cmd += ["-config", san_ext_file]
        print(f"    SAN: {san_str}")

    subprocess.run(csr_cmd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("[*] Signing server certificate with CA...")

    sign_cmd = [
        "openssl", "x509", "-req",
        "-in",          f"{cert_dir}/server.csr",
        "-CA",          f"{cert_dir}/ca.pem",
        "-CAkey",       f"{cert_dir}/ca.key",
        "-CAcreateserial",
        "-out",         f"{cert_dir}/server.pem",
        "-days",        "3650",
    ]

    # Add SAN extension during signing
    if san:
        san_str = ",".join(f"DNS:{s}" for s in san)
        sign_ext_file = "/tmp/eapx_sign_ext.cnf"
        with open(sign_ext_file, "w") as f:
            f.write(f"subjectAltName = {san_str}\n")
        sign_cmd += ["-extfile", sign_ext_file]

    subprocess.run(sign_cmd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Generate and save fingerprint info
    fp_result = subprocess.run(
        ["openssl", "x509", "-in", f"{cert_dir}/server.pem",
         "-noout", "-fingerprint", "-sha256"],
        capture_output=True, text=True
    )
    fingerprint = fp_result.stdout.strip()

    subj_result = subprocess.run(
        ["openssl", "x509", "-in", f"{cert_dir}/server.pem",
         "-noout", "-subject", "-issuer"],
        capture_output=True, text=True
    )

    fp_info = {
        "generated_at": str(datetime.datetime.now()),
        "fingerprint": fingerprint,
        "subject": srv_subj,
        "ca_subject": ca_subj,
        "san": san or [],
        "details": subj_result.stdout.strip(),
    }

    with open(os.path.join(cert_dir, "fingerprint.json"), "w") as f:
        json.dump(fp_info, f, indent=2)

    # Cleanup temp files
    for tmp in ["/tmp/eapx_san.cnf", "/tmp/eapx_sign_ext.cnf"]:
        try:
            os.remove(tmp)
        except OSError:
            pass

    print(f"\n[+] Certificates generated in {cert_dir}/")
    print(f"    ca.pem | ca.key | server.pem | server.key | server.csr")
    if fingerprint:
        print(f"    {fingerprint}")

    # ── Generate DH parameters (Bug #5 fix) ──
    dh_path = os.path.join(cert_dir, "dh.pem")
    if not os.path.exists(dh_path):
        print("[*] Generating DH parameters (2048-bit, this takes ~10-30s)...")
        subprocess.run([
            "openssl", "dhparam", "-out", dh_path, "2048"
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[+] DH params generated")
    else:
        print("[+] DH params already exist — skipping")


def generate_certs_from_clone(metadata):
    """
    Generate certificates using cloned RADIUS cert metadata.
    Accepts the dict returned by cert_clone.clone_radius_cert().
    """

    if not metadata:
        print("[!] No cloned metadata — generating generic certs")
        generate_certs()
        return

    print("\n[*] Generating CLONED certificates with real AP metadata...")

    generate_certs(
        cn=metadata.get("cn")         or "FakeRADIUS",
        org=metadata.get("org")       or "Corp",
        country=metadata.get("country") or "IN",
        ou=metadata.get("ou"),
        san=metadata.get("san"),
        issuer_cn=metadata.get("issuer_cn"),
        issuer_org=metadata.get("issuer_org"),
    )
