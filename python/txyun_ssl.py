# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# File: txyun_ssl.py
# Description: Script to apply for Tencent Cloud SSL Certificate and handle domain verification via Cloudflare DNS.
# Author: Peter
# -----------------------------------------------------------------------------

import os
import hashlib
import hmac
import json
import sys
import time
import logging
import argparse
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any

import requests
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()


def get_env_variable(name: str) -> str:
    """Retrieve environment variable or exit if not found."""
    value = os.getenv(name)
    if not value:
        logging.error(f"Environment variable {name} not set.")
        sys.exit(1)
    return value


def sign(key: bytes, msg: str) -> bytes:
    """Generate HMAC-SHA256 signature."""
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def create_authorization(
    secret_id: str, secret_key: str, service: str, host: str, action: str, payload: str
) -> Tuple[str, int]:
    """Create authorization header for Tencent Cloud API."""
    algorithm = "TC3-HMAC-SHA256"
    timestamp = int(time.time())
    date = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d")
    credential_scope = f"{date}/{service}/tc3_request"

    # Step 1: Create canonical request
    http_request_method = "POST"
    canonical_uri = "/"
    canonical_querystring = ""
    ct = "application/json; charset=utf-8"
    canonical_headers = (
        f"content-type:{ct}\nhost:{host}\nx-tc-action:{action.lower()}\n"
    )
    signed_headers = "content-type;host;x-tc-action"
    hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    canonical_request = (
        f"{http_request_method}\n"
        f"{canonical_uri}\n"
        f"{canonical_querystring}\n"
        f"{canonical_headers}\n"
        f"{signed_headers}\n"
        f"{hashed_request_payload}"
    )

    # Step 2: Create string to sign
    hashed_canonical_request = hashlib.sha256(
        canonical_request.encode("utf-8")
    ).hexdigest()
    string_to_sign = (
        f"{algorithm}\n{timestamp}\n{credential_scope}\n{hashed_canonical_request}"
    )

    # Step 3: Calculate signature
    secret_date = sign(f"TC3{secret_key}".encode("utf-8"), date)
    secret_service = sign(secret_date, service)
    secret_signing = sign(secret_service, "tc3_request")
    signature = hmac.new(
        secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    # Step 4: Assemble authorization
    authorization = (
        f"{algorithm} "
        f"Credential={secret_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )

    return authorization, timestamp


def apply_certificate(
    secret_id: str, secret_key: str, region: str, payload: str
) -> str:
    """Apply for a Tencent Cloud SSL certificate and return CertificateId."""
    service = "ssl"
    host = "ssl.tencentcloudapi.com"
    action = "ApplyCertificate"
    version = "2019-12-05"

    authorization, timestamp = create_authorization(
        secret_id, secret_key, service, host, action, payload
    )

    headers = {
        "Authorization": authorization,
        "Content-Type": "application/json; charset=utf-8",
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Version": version,
    }
    if region:
        headers["X-TC-Region"] = region

    try:
        response = requests.post(f"https://{host}/", headers=headers, data=payload)
        response.raise_for_status()
        response_data = response.json()
        logging.info("Apply Certificate Response:")
        logging.info(json.dumps(response_data, indent=2))
    except requests.exceptions.RequestException as err:
        logging.error(f"Request failed: {err}")
        sys.exit(1)

    # 获取证书域名验证信息
    certificate_id = response_data.get("CertificateId")
    if certificate_id:
        logging.info(f"Obtained CertificateId: {certificate_id}")
        return certificate_id
    else:
        logging.error("Failed to obtain CertificateId.")
        sys.exit(1)


def get_cloudflare_zone_id(api_token: str, domain: str) -> Optional[str]:
    """Retrieve Cloudflare Zone ID for a given domain."""
    url = "https://api.cloudflare.com/client/v4/zones"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    params = {"name": domain}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        zones = response.json().get("result", [])
        if zones:
            zone_id = zones[0]["id"]
            logging.info(f"Retrieved Zone ID for {domain}: {zone_id}")
            return zone_id
        else:
            logging.error(f"No zone found for domain: {domain}")
            return None
    except requests.exceptions.RequestException as err:
        logging.error(f"Failed to get Zone ID: {err}")
        return None


def add_cloudflare_dns_record(
    api_token: str, zone_id: str, dns_key: str, dns_value: str
) -> None:
    """Add a DNS TXT record in Cloudflare for domain verification."""
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    data = {
        "type": "TXT",
        "name": dns_key,
        "content": dns_value,
        "ttl": 120,
        "proxied": False,
    }
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        if result.get("success"):
            logging.info(f"Successfully added DNS record: {dns_key}")
        else:
            logging.error(f"Failed to add DNS record: {result.get('errors')}")
    except requests.exceptions.RequestException as err:
        logging.error(f"Error adding DNS record: {err}")


def delete_cloudflare_dns_record(
    api_token: str, zone_id: str, dns_key: str, dns_value: str
) -> None:
    """Delete a DNS TXT record in Cloudflare after verification."""
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    params = {
        "type": "TXT",
        "name": dns_key,
        "content": dns_value,
    }
    try:
        # Retrieve the DNS record ID
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        records = response.json().get("result", [])

        if not records:
            logging.error(f"No DNS record found for {dns_key} with value {dns_value}")
            return

        for record in records:
            record_id = record.get("id")
            if not record_id:
                logging.error("DNS record ID not found.")
                continue

            # Delete the DNS record
            delete_url = f"{url}/{record_id}"
            del_response = requests.delete(delete_url, headers=headers)
            del_response.raise_for_status()
            del_result = del_response.json()

            if del_result.get("success"):
                logging.info(f"Successfully deleted DNS record: {dns_key}")
            else:
                logging.error(
                    f"Failed to delete DNS record: {del_result.get('errors')}"
                )
    except requests.exceptions.RequestException as err:
        logging.error(f"Error deleting DNS record: {err}")


def describe_certificate(
    secret_id: str, secret_key: str, region: str, certificate_id: str
) -> Dict[str, Any]:
    """Describe certificate to retrieve domain verification details."""
    service = "ssl"
    host = "ssl.tencentcloudapi.com"
    action = "DescribeCertificate"
    version = "2019-12-05"
    payload = json.dumps({"CertificateId": certificate_id})

    authorization, timestamp = create_authorization(
        secret_id, secret_key, service, host, action, payload
    )

    headers = {
        "Authorization": authorization,
        "Content-Type": "application/json; charset=utf-8",
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Version": version,
    }
    if region:
        headers["X-TC-Region"] = region

    try:
        response = requests.post(f"https://{host}/", headers=headers, data=payload)
        response.raise_for_status()
        response_data = response.json()
        logging.info("Describe Certificate Response:")
        logging.info(json.dumps(response_data, indent=2))
        return response_data.get("Response", {})
    except requests.exceptions.RequestException as err:
        logging.error(f"Request failed: {err}")
        sys.exit(1)


def check_certificate_domain_verification(
    secret_id: str, secret_key: str, region: str, certificate_id: str
) -> str:
    """Check certificate domain verification status."""
    service = "ssl"
    host = "ssl.tencentcloudapi.com"
    action = "CheckCertificateDomainVerification"
    version = "2019-12-05"
    payload = json.dumps({"CertificateId": certificate_id})

    authorization, timestamp = create_authorization(
        secret_id, secret_key, service, host, action, payload
    )

    headers = {
        "Authorization": authorization,
        "Content-Type": "application/json; charset=utf-8",
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Version": version,
    }
    if region:
        headers["X-TC-Region"] = region

    try:
        response = requests.post(f"https://{host}/", headers=headers, data=payload)
        response.raise_for_status()
        response_data = response.json()
        verification_status = response_data.get("Response", {}).get(
            "VerificationStatus", "UNKNOWN"
        )
        logging.info(f"Domain verification status: {verification_status}")
        return verification_status
    except requests.exceptions.RequestException as err:
        logging.error(f"Request failed: {err}")
        return "ERROR"


# ...existing code...


def commit_certificate_information(
    secret_id: str, secret_key: str, region: str, certificate_id: str
) -> Dict[str, Any]:
    """Commit certificate information to Tencent Cloud."""
    service = "ssl"
    host = "ssl.tencentcloudapi.com"
    action = "CommitCertificateInformation"
    version = "2019-12-05"
    payload = json.dumps({"CertificateId": certificate_id})

    authorization, timestamp = create_authorization(
        secret_id, secret_key, service, host, action, payload
    )

    headers = {
        "Authorization": authorization,
        "Content-Type": "application/json; charset=utf-8",
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Version": version,
    }
    if region:
        headers["X-TC-Region"] = region

    try:
        response = requests.post(f"https://{host}/", headers=headers, data=payload)
        response.raise_for_status()
        response_data = response.json()
        logging.info("Commit Certificate Information Response:")
        logging.info(json.dumps(response_data, indent=2))
        return response_data.get("Response", {})
    except requests.exceptions.RequestException as err:
        logging.error(f"Request failed: {err}")
        sys.exit(1)


def main() -> None:
    """Main function to apply for SSL certificate, handle DNS records, verify domain, and commit certificate information."""
    parser = argparse.ArgumentParser(
        description="Apply for Tencent Cloud SSL Certificate."
    )
    parser.add_argument("--region", type=str, default="", help="Region")
    parser.add_argument("--payload", type=str, required=True, help="JSON payload")
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=5,
        help="Maximum number of verification attempts",
    )
    parser.add_argument(
        "--check-interval",
        type=int,
        default=60,
        help="Interval between verification checks in seconds",
    )
    args = parser.parse_args()

    secret_id = get_env_variable("TENCENT_CLOUD_SECRET_ID")
    secret_key = get_env_variable("TENCENT_CLOUD_SECRET_KEY")
    cloudflare_api_token = get_env_variable("CLOUDFLARE_API_TOKEN")

    # Apply for the certificate
    certificate_id = apply_certificate(secret_id, secret_key, args.region, args.payload)

    # Describe the certificate to get domain verification details
    describe_resp = describe_certificate(
        secret_id, secret_key, args.region, certificate_id
    )
    dv_auth_detail = describe_resp.get("DvAuthDetail", {})

    if not dv_auth_detail:
        logging.error("No domain verification information found.")
        sys.exit(1)

    domain = dv_auth_detail.get("DvAuthDomain")
    dv_auths = dv_auth_detail.get("DvAuths", [])

    if not domain or not dv_auths:
        logging.error("Incomplete domain verification information.")
        sys.exit(1)

    logging.info("Adding DNS records for domain verification...")

    zone_id = get_cloudflare_zone_id(cloudflare_api_token, domain)
    if not zone_id:
        logging.error(f"Cannot find Zone ID for domain: {domain}")
        sys.exit(1)

    for auth in dv_auths:
        dns_key = auth.get("DvAuthKey")
        dns_value = auth.get("DvAuthValue")
        if dns_key and dns_value:
            add_cloudflare_dns_record(cloudflare_api_token, zone_id, dns_key, dns_value)
        else:
            logging.error("Invalid DvAuth details.")
            sys.exit(1)

    logging.info(
        f"Started domain verification. Maximum attempts: {args.max_attempts}, Interval: {args.check_interval} seconds."
    )

    for attempt in range(1, args.max_attempts + 1):
        logging.info(
            f"Attempt {attempt} of {args.max_attempts}: Checking domain verification status..."
        )
        verification_status = check_certificate_domain_verification(
            secret_id, secret_key, args.region, certificate_id
        )

        if verification_status == "VERIFIED":
            logging.info("Domain verification successful. Deleting DNS records...")
            for auth in dv_auths:
                dns_key = auth.get("DvAuthKey")
                dns_value = auth.get("DvAuthValue")
                if dns_key and dns_value:
                    delete_cloudflare_dns_record(
                        cloudflare_api_token, zone_id, dns_key, dns_value
                    )
                else:
                    logging.error("Invalid DvAuth details.")
            logging.info("DNS records deleted successfully.")

            # Commit certificate information
            commit_resp = commit_certificate_information(
                secret_id, secret_key, args.region, certificate_id
            )
            logging.info("Commit Certificate Information Result:")
            logging.info(json.dumps(commit_resp, indent=2))
            sys.exit(0)
        else:
            logging.warning(f"Domain verification status: {verification_status}")
            if attempt < args.max_attempts:
                logging.info(
                    f"Waiting for {args.check_interval} seconds before next check..."
                )
                time.sleep(args.check_interval)
            else:
                logging.error(
                    "Maximum verification attempts reached. Domain verification not successful."
                )

    logging.info("You may need to manually check and delete DNS records if necessary.")
    sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("txyun_ssl.log"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    main()
