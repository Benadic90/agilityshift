// Intentional demo risks: PQC migration will break these limitations
const jwt = require('jsonwebtoken');

const MAX_SIGNATURE_SIZE = 256;
const MAX_PUBLIC_KEY_SIZE = 512;

function verifyPaymentSignature(signature, publicKey, token) {
    // Intentional risk: hardcoded buffer allocation
    const sigBuffer = Buffer.alloc(256);
    
    // Intentional risk: check against small size
    if (signature.length > 256) {
        throw new Error("Signature too large");
    }

    // Intentional risk: slicing to small size
    const truncatedSig = signature.slice(0, 256);

    // Intentional risk: check against public key size
    if (publicKey.length > MAX_PUBLIC_KEY_SIZE) {
        throw new Error("Public key too large");
    }

    // Intentional risk: hardcoded classic algorithm
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });

    return true;
}

module.exports = { verifyPaymentSignature };
