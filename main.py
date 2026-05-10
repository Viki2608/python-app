import urllib.parse
from fastapi import FastAPI, Header, HTTPException, status, Request
from cryptography import x509
from cryptography.hazmat.backends import default_backend

app = FastAPI(title="Identity Validator")


def get_cn_from_cert(cert_pem: str) -> str:
    try:
        # 1. URL-decode the certificate from NGINX
        decoded_cert = urllib.parse.unquote(cert_pem)

        # 2. Encode to bytes
        cert_data = decoded_cert.encode("utf-8")

        # 3. Parse PEM certificate
        cert = x509.load_pem_x509_certificate(
            cert_data,
            default_backend()
        )

        # 4. Extract CN
        cn_attributes = cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )

        if not cn_attributes:
            return ""

        return cn_attributes[0].value

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid Certificate: {str(e)}"
        )


@app.get("/validate")
async def validate_user(
    request: Request,
    user_id: str
):
    ssl_client_cert = (
    request.headers.get("x-forwarded-tls-client-cert") or
    request.headers.get("x-ssl-client-cert") or
    request.headers.get("ssl-client-cert")
)
    # Print all headers
    print("\n===== Incoming Headers =====")
    for key, value in request.headers.items():
        print(f"{key}: {value}")
    print("============================\n")

    # Print raw cert header
    print(f"Received raw cert header:\n{ssl_client_cert}")

    if not ssl_client_cert:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Client certificate missing"
        )

    # Extract CN from certificate
    cert_user_id = get_cn_from_cert(ssl_client_cert)

    print(f"Certificate CN: {cert_user_id}")
    print(f"Requested user_id: {user_id}")

    # Compare identity
    if cert_user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Identity Mismatch: Cert represents "
                f"'{cert_user_id}', but request claims "
                f"to be '{user_id}'"
            )
        )

    return {
        "status": "success",
        "message": f"Identity verified for user: {cert_user_id}"
    }