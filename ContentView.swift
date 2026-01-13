//
//  ContentView.swift
//  gpteffort
//
//  Created by Nicholas Oakley on 12/29/25.
//

import SwiftUI
import UniformTypeIdentifiers
import Security

struct ContentView: View {
    // Server URL (e.g., https://192.168.1.65:8443/upload)
    @State private var serverURLString: String = "https://192.168.1.65:8443/upload"

    // Certificate bundle names (without extensions)
    @State private var p12Name: String = "ios-client"  // expects ios-client.p12 in bundle
    @State private var p12Password: String = ""        // password used when exporting the .p12
    @State private var caName: String = "rootCA"       // expects rootCA.der in bundle

    // Loaded security objects
    @State private var identity: SecIdentity?
    @State private var clientCertificate: SecCertificate?
    @State private var pinnedCACertificate: SecCertificate?

    // File selection
    @State private var selectedFileURL: URL?
    @State private var isShowingPicker = false

    // UI state
    @State private var status: String = ""
    @State private var isUploading: Bool = false

    // Keep uploader alive (prevents delegate deallocation / EXC_BAD_ACCESS)
    @State private var uploader = MTLSUploader()

    var body: some View {
        NavigationStack {
            Form {
                Section("Server") {
                    TextField("https://<host>:<port>/upload", text: $serverURLString)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .textSelection(.enabled)

                    Button("Quick set: 192.168.1.65") {
                        serverURLString = "https://192.168.1.65:8443/upload"
                        status = "Server URL set to 192.168.1.65"
                    }
                    .buttonStyle(.bordered)
                }

                Section("Certificates (from app bundle)") {
                    HStack {
                        TextField(".p12 name (no extension)", text: $p12Name)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        SecureField(".p12 password", text: $p12Password)
                    }

                    TextField("CA name (DER, no extension)", text: $caName)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()

                    Button("Load Certificates") {
                        loadCertificates()
                    }
                    .buttonStyle(.borderedProminent)

                    if identity != nil {
                        Label("Client identity loaded", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                    } else {
                        Label("Client identity not loaded", systemImage: "xmark.seal")
                            .foregroundStyle(.secondary)
                    }

                    if pinnedCACertificate != nil {
                        Label("CA loaded (pinning enabled)", systemImage: "lock.shield")
                            .foregroundStyle(.green)
                    } else {
                        Label("CA not loaded (no pinning)", systemImage: "lock.open")
                            .foregroundStyle(.secondary)
                    }
                }

                Section("File") {
                    Button("Choose File") { isShowingPicker = true }
                        .buttonStyle(.bordered)

                    if let url = selectedFileURL {
                        Text("Selected: \(url.lastPathComponent)")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("No file selected")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }

                Section("Actions") {
                    Button {
                        status = "✅ Upload button tapped"
                        print("✅ Upload button tapped")

                        Task {
                            await uploadTapped()
                        }
                    } label: {
                        if isUploading {
                            HStack(spacing: 8) {
                                ProgressView()
                                Text("Uploading…")
                            }
                        } else {
                            Text("Upload")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isUploading || selectedFileURL == nil || identity == nil)

                    Text("debug: uploading=\(isUploading) file=\(selectedFileURL != nil) identity=\(identity != nil)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("Status") {
                    Text(status.isEmpty ? "(status empty)" : status)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
            .navigationTitle("Secure Upload DEBUG")
            .fileImporter(
                isPresented: $isShowingPicker,
                allowedContentTypes: [.item],
                allowsMultipleSelection: false
            ) { result in
                switch result {
                case .success(let urls):
                    selectedFileURL = urls.first
                    status = "File selected: \(urls.first?.lastPathComponent ?? "(unknown)")"
                case .failure(let error):
                    status = "File selection failed: \(error.localizedDescription)"
                }
            }
        }
    }

    private func loadCertificates() {
        status = "Loading certificates…"

        // Load client identity (.p12)
        do {
            let (id, cert) = try CertificateStore.loadIdentity(p12Named: p12Name, password: p12Password)
            self.identity = id
            self.clientCertificate = cert
            status = "✅ Client identity loaded"
        } catch {
            self.identity = nil
            self.clientCertificate = nil
            status = "❌ Failed to load .p12: \(error.localizedDescription)"
        }

        // Load pinned CA (.der) (optional)
        do {
            let ca = try CertificateStore.loadCACertificate(named: caName)
            self.pinnedCACertificate = ca
            status += "\n✅ CA loaded (pinning enabled)"
        } catch {
            self.pinnedCACertificate = nil
            status += "\n⚠️ Failed to load CA: \(error.localizedDescription)"
        }
    }

    @MainActor
    private func uploadTapped() async {
        status = "🚀 uploadTapped() started"
        isUploading = true
        defer { isUploading = false }

        guard let fileURL = selectedFileURL else {
            status = "❌ No file selected"
            return
        }
        guard let identity, let clientCertificate else {
            status = "❌ Client identity not loaded"
            return
        }
        guard let url = URL(string: serverURLString) else {
            status = "❌ Invalid server URL"
            return
        }

        status = "🌐 Connecting…"

        do {
            try await uploader.upload(
                fileURL: fileURL,
                to: url,
                identity: identity,
                certificate: clientCertificate,
                pinnedCACert: pinnedCACertificate
            )
            status = "✅ Upload completed (check nginx/app logs + uploads folder)"
        } catch {
            let ns = error as NSError
            status =
            """
            ❌ Upload failed
            \(error.localizedDescription)
            domain: \(ns.domain)
            code: \(ns.code)
            """
        }
    }
}

#Preview {
    ContentView()
}

