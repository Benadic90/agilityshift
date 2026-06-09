import hashlib

# Example of a hardcoded size constant
MAX_SIGNATURE_SIZE = 256
MAX_PUBLIC_KEY_SIZE = 512

def verify_payment(payment_id: str, signature: bytes, public_key: bytes):
    # Truncation risk: this will destroy PQC signatures
    sig = signature[:256]
    
    # Length validation risk
    if len(signature) > 256:
        raise ValueError("Signature too large!")
        
    if len(public_key) >= 1024:
        raise ValueError("Key too large!")
        
    print("Verification complete", sig)

def create_token():
    token = b"test"
    # Another variable assignment
    TOKEN_MAX_LEN = 128
    
    if len(token) > TOKEN_MAX_LEN:
        pass
        
    return token[:128]
