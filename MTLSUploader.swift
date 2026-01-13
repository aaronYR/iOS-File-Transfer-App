import Foundation
import Security

final class MTLSURLSessionDelegate: NSObject, URLSessionDelegate {
    private let identity: SecIdentity
    private let certificate: SecCertificate
    private let pinnedCACert: SecCertificate?

    init(identity: SecIdentity, certificate: SecCertificate, pinnedCACert: SecCertificate?) {
        self.identity = identity
        self.certificate = certificate
        self.pinnedCACert = pinnedCACert
    }

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

        let method = challenge.protectionSpace.authenticationMethod
        print("🔐 TLS challenge:", method, "host:", challenge.protectionSpace.host)

        switch method {

        case NSURLAuthenticationMethodClientCertificate:
            // Present client identity (mTLS)
            print("🔑 Providing client certificate")
            let credential = URLCredential(identity: identity,
                                           certificates: [certificate],
                                           persistence: .forSession)
            completionHandler(.useCredential, credential)

        case NSURLAuthenticationMethodServerTrust:
            // Pin CA (optional) and evaluate trust
            guard let trust = challenge.protectionSpace.serverTrust else {
                print("❌ No serverTrust in challenge")
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }

            // IMPORTANT: bind trust evaluation to the host (especially for IP URLs)
            let host = challenge.protectionSpace.host
            let policy = SecPolicyCreateSSL(true, host as CFString)
            SecTrustSetPolicies(trust, policy)

            if let pinnedCACert {
                print("📌 Applying CA pinning (anchor to pinned CA)")
                SecTrustSetAnchorCertificates(trust, [pinnedCACert] as CFArray)
                SecTrustSetAnchorCertificatesOnly(trust, true)
            } else {
                print("⚠️ No pinned CA provided (default trust store)")
            }

            var trustError: CFError?
            if SecTrustEvaluateWithError(trust, &trustError) {
                print("✅ Server trust OK")
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                print("❌ Server trust FAILED:", String(describing: trustError))
                completionHandler(.cancelAuthenticationChallenge, nil)
            }

        default:
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

final class MTLSUploader: NSObject {
    enum UploadError: Error, LocalizedError {
        case noHTTPResponse
        case badResponse(Int, String)

        var errorDescription: String? {
            switch self {
            case .noHTTPResponse:
                return "No HTTP response"
            case .badResponse(let code, let body):
                return "Server rejected upload (HTTP \(code)). Body: \(body)"
            }
        }
    }

    // Strong reference to prevent delegate from deallocating mid-TLS
    private var delegateRef: MTLSURLSessionDelegate?

    func upload(fileURL: URL,
                to url: URL,
                identity: SecIdentity,
                certificate: SecCertificate,
                pinnedCACert: SecCertificate?) async throws {

        print("➡️ Starting upload to:", url.absoluteString)

        let delegate = MTLSURLSessionDelegate(identity: identity,
                                              certificate: certificate,
                                              pinnedCACert: pinnedCACert)
        self.delegateRef = delegate
        defer { self.delegateRef = nil }

        // Add timeouts so it doesn't look like "nothing happens"
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 30

        let session = URLSession(configuration: config,
                                 delegate: delegate,
                                 delegateQueue: nil)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 15

        let boundary = "Boundary-\(UUID().uuidString)"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")

        // Security-scoped access is often required for Files picker URLs
        let scoped = fileURL.startAccessingSecurityScopedResource()
        defer { if scoped { fileURL.stopAccessingSecurityScopedResource() } }

        let fileData = try Data(contentsOf: fileURL)
        let filename = fileURL.lastPathComponent

        var body = Data()
        let lb = "\r\n"

        body.append("--\(boundary)\(lb)".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"file\"; filename=\"\(filename)\"\(lb)".data(using: .utf8)!)
        body.append("Content-Type: application/octet-stream\(lb)\(lb)".data(using: .utf8)!)
        body.append(fileData)
        body.append(lb.data(using: .utf8)!)
        body.append("--\(boundary)--\(lb)".data(using: .utf8)!)

        let (data, response) = try await session.upload(for: request, from: body)

        guard let http = response as? HTTPURLResponse else {
            throw UploadError.noHTTPResponse
        }

        let respText = String(data: data, encoding: .utf8) ?? "<non-utf8 \(data.count) bytes>"
        print("⬅️ HTTP status:", http.statusCode)
        print("⬅️ Response body:", respText)

        guard (200..<300).contains(http.statusCode) else {
            throw UploadError.badResponse(http.statusCode, respText)
        }

        print("✅ Upload succeeded")
    }
}

