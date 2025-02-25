use openssl::pkey::PKey;

use crate::{internal, Error};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Deserialize;

#[derive(Deserialize)]
struct STHJson {
    tree_size: u64,
    timestamp: u64,
    sha256_root_hash: String,
    tree_head_signature: String,
}

/// An unverified *signed tree head* (STH), as returned from the server. This encapsulate the state of the tree at
/// some point in time.
///
/// This struct stores the signature but does not store the public key or log id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub timestamp: u64,
    pub root_hash: [u8; 32],
    /// Digitally signed struct
    pub signature: Vec<u8>,
}

impl SignedTreeHead {
    /// Verify the contained signature against the log's public key.
    pub fn verify(&self, pub_key: &PKey<openssl::pkey::Public>) -> Result<(), Error> {
        let verify_body = self.get_body();
        internal::verify_dss(&self.signature, pub_key, &verify_body).map_err(|e| match e {
            Error::InvalidSignature(desc) => {
                Error::InvalidSignature(format!("When checking STH signature: {}", &desc))
            }
            other => other,
        })
    }

    /// Get the body of the STH, which is the data that is signed.
    pub fn get_body(&self) -> Vec<u8> {
        let mut verify_body: Vec<u8> = Vec::new();
        /*
          From go source:
          type TreeHeadSignature struct {
            Version        Version       `tls:"maxval:255"`
            SignatureType  SignatureType `tls:"maxval:255"` // == TreeHashSignatureType
            Timestamp      uint64
            TreeSize       uint64
            SHA256RootHash SHA256Hash
          }
        */
        verify_body.push(0); // Version = 0
        verify_body.push(1); // SignatureType = TreeHashSignatureType
        verify_body.extend_from_slice(&self.timestamp.to_be_bytes()); // Timestamp
        verify_body.extend_from_slice(&self.tree_size.to_be_bytes()); // TreeSize
        verify_body.extend_from_slice(&self.root_hash);
        verify_body
    }

    /// Create a SignedTreeHead from a JSON string
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let sth_json: STHJson = serde_json::from_str(json)
            .map_err(|e| Error::InvalidArgument(format!("Failed to parse JSON: {}", e)))?;

        // Decode base64 root hash
        let root_hash = BASE64
            .decode(sth_json.sha256_root_hash)
            .map_err(|e| Error::InvalidArgument(format!("Failed to decode root hash: {}", e)))?;

        // Convert root_hash into fixed size array
        let root_hash: [u8; 32] = root_hash
            .try_into()
            .map_err(|_| Error::InvalidArgument("Root hash must be 32 bytes".to_string()))?;

        // Decode base64 signature
        let signature = BASE64
            .decode(sth_json.tree_head_signature)
            .map_err(|e| Error::InvalidArgument(format!("Failed to decode signature: {}", e)))?;

        Ok(SignedTreeHead {
            tree_size: sth_json.tree_size,
            timestamp: sth_json.timestamp,
            root_hash,
            signature,
        })
    }
}
