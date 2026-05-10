import urllib.parse
import base64
import logging
from fastapi import FastAPI, HTTPException, status, Request
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DynamicProxyValidator")

app = FastAPI(title="Adaptive Identity Validator")

def get_cn_from_cert(raw_cert: str, format_type: str) -> str:
    """Decodes cert based on format: 'pem' (NGINX/Traefik) or 'der' (HAProxy)"""
    try:
        if format_type == "der":
            cert_data = base64.b64decode(raw_cert)
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
        else:
            decoded_pem = urllib.parse.unquote(raw_cert)
            cert = x509.load_pem_x509_certificate(decoded_pem.encode(), default_backend())

        cn_attributes = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return cn_attributes[0].value if cn_attributes else "No-CN"
    except Exception as e:
        logger.error(f"Cert parse error: {str(e)}")
        return None

@app.get("/validate")
async def validate_user(request: Request, user_id: str):
    headers = request.headers
    detected_proxy = "Unknown"
    cert_value = None
    cert_format = "pem"
    used_header = "None"

    # 1. Detection Logic (Fingerprinting)
    # Check for HAProxy (using our custom 'x-proxy-id' header signature)
    if headers.get("x-proxy-id") == "haproxy-ingress":
        detected_proxy = "HAProxy"
        used_header = "ssl-client-cert"
        cert_value = headers.get(used_header)
        cert_format = "der"
    
    # Check for Traefik (Gateway API or Ingress)
    elif headers.get("x-forwarded-tls-client-cert"):
        detected_proxy = "Traefik"
        used_header = "x-forwarded-tls-client-cert"
        cert_value = headers.get(used_header)
        cert_format = "pem"

    # Check for NGINX Ingress
    elif headers.get("ssl-client-cert"):
        detected_proxy = "NGINX Ingress"
        used_header = "ssl-client-cert"
        cert_value = headers.get(used_header)
        cert_format = "pem"

    # 2. Validation & Logging Logic
    logger.info(f"--- Request Received ---")
    logger.info(f"Detected Proxy: {detected_proxy}")
    logger.info(f"Header Received: {used_header}")

    if not cert_value:
        logger.warning(f"Validation Failed: No cert found in header '{used_header}' via {detected_proxy}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail=f"No client certificate found in {used_header}"
        )

    cert_cn = get_cn_from_cert(cert_value, cert_format)

    if not cert_cn or cert_cn != user_id:
        logger.warning(f"Auth Failed: Proxy={detected_proxy}, Header={used_header}, CertCN={cert_cn}, Input={user_id}")
        raise HTTPException(status_code=403, detail="Identity Mismatch")

    logger.info(f"Auth Success: Proxy={detected_proxy}, User={cert_cn}")
    
    return {
        "status": "success",
        "detected_proxy": detected_proxy,
        "header_used": used_header,
        "verified_user": cert_cn
    }