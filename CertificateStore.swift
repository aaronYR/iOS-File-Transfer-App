import Foundation
import Security

enum CertificateStoreError: Error, LocalizedError {
    case resourceNotFound(String)
    case p12ImportFailed(OSStatus)
    case identityMissing
    case certificateCreateFailed

    var errorDescription: String? {
        switch self {
        case .resourceNotFound(let name): return "Resource not found: \(name)"
        case .p12ImportFailed(let status): return "PKCS12 import failed: \(status)"
        case .identityMissing: return "Identity missing from PKCS12"
        case .certificateCreateFailed: return "Failed to create certificate"
        }
    }
}

struct CertificateStore {
    static func loadIdentity(p12Named name: String, password: String) throws -> (SecIdentity, SecCertificate) {
        guard let url = Bundle.main.url(forResource: name, withExtension: "p12") else {
            throw CertificateStoreError.resourceNotFound("\(name).p12")
        }

        let data = try Data(contentsOf: url)
        let options: [String: Any] = [kSecImportExportPassphrase as String: password]

        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)

        guard status == errSecSuccess else {
            throw CertificateStoreError.p12ImportFailed(status)
        }

        guard
            let array = items as? [[String: Any]],
            let dict = array.first
        else {
            throw CertificateStoreError.identityMissing
        }

        guard let identityAny = dict[kSecImportItemIdentity as String] else {
            throw CertificateStoreError.identityMissing
        }

        let identityCF = identityAny as CFTypeRef
        guard CFGetTypeID(identityCF) == SecIdentityGetTypeID() else {
            throw CertificateStoreError.identityMissing
        }
        let identity = identityCF as! SecIdentity

        // Prefer leaf cert from chain if present
        if let chainAny = dict[kSecImportItemCertChain as String] as? [Any],
           let first = chainAny.first {
            let firstCF = first as CFTypeRef
            if CFGetTypeID(firstCF) == SecCertificateGetTypeID() {
                let leaf = firstCF as! SecCertificate
                return (identity, leaf)
            }
        }

        // Fallback: copy cert from identity
        var certOut: SecCertificate?
        SecIdentityCopyCertificate(identity, &certOut)
        guard let leaf = certOut else { throw CertificateStoreError.identityMissing }
        return (identity, leaf)
    }

    static func loadCACertificate(named name: String) throws -> SecCertificate {
        guard let url = Bundle.main.url(forResource: name, withExtension: "der") else {
            throw CertificateStoreError.resourceNotFound("\(name).der")
        }
        let data = try Data(contentsOf: url)
        guard let cert = SecCertificateCreateWithData(nil, data as CFData) else {
            throw CertificateStoreError.certificateCreateFailed
        }
        return cert
    }
}

