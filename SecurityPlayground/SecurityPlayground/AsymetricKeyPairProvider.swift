//
//  AsymetricKeyPairProvider.swift
//  SecurityPlayground
//
//  Created by Guillaume Bohr on 21/03/2025.
//

import Foundation
import LocalAuthentication

struct KeyUsageError: Error {
    enum ErrorKind {
        case invalidAlgorithm
    }

    let description: String
    let kind: ErrorKind
}

struct AsymetricKeyPairProvider: Any {
    static let secKeyAttrLabel = "com.bohrgu.secpg.asymkeypair.secureenclave.label"
    static let secKeyAttrTag = "com.bohrgu.secpg.asymkeypair.secureenclave.tag"
    let privateKeyRef: SecKey?
    
    init() {
        AsymetricKeyPairProvider.deletePreviousKeyPair()
        
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .and, .applicationPassword],
            nil)!
        
        let context = LAContext()
        context.setCredential("password".data(using: .utf8), type: .applicationPassword)
        
        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecAttrLabel: AsymetricKeyPairProvider.secKeyAttrLabel,
            kSecClass: kSecClassKey,
            kSecUseAuthenticationContext: context,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: AsymetricKeyPairProvider.secKeyAttrTag,
                kSecAttrAccessControl: accessControl
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes, &error) else {
            print(error!.takeRetainedValue() as Error)
            self.privateKeyRef = nil
            return
        }
        
        self.privateKeyRef = privateKey
    }
    
    static func deletePreviousKeyPair() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: AsymetricKeyPairProvider.secKeyAttrLabel
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        if (status == errSecSuccess) {
            print("Previous key pair deleted")
        }
        else if (status == errSecItemNotFound) {
            print("No previous key pair found")
        }
    }
    
    func getPrivateKey(context: LAContext? = nil) -> SecKey? {
        var attributes: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: AsymetricKeyPairProvider.secKeyAttrLabel,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnRef as String: true,
        ]
        
        if let context = context {
            attributes[kSecUseAuthenticationContext as String] = context
        }
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &item)
        
        if (status == errSecSuccess) {
            return (item as! SecKey)
        } else {
            return nil
        }
    }
    
    func getPublicKey() -> SecKey {
        return SecKeyCopyPublicKey(self.privateKeyRef!)!
    }
    
    func sign(data: Data, privateKey: SecKey) throws -> Data? {
        if (SecKeyIsAlgorithmSupported(privateKey, .sign, .ecdsaSignatureMessageX962SHA256)) {
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(privateKey,
                                                        .ecdsaSignatureMessageX962SHA256,
                                                        data as CFData,
                                                        &error) as Data? else {
                throw error!.takeRetainedValue() as Error
            }
            return signature
        }
        return nil
    }
    
    func verify(data: Data, publicKey: SecKey, signature: Data) throws -> Bool {
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, .ecdsaSignatureMessageX962SHA256) else {
            throw KeyUsageError(description: "Invalid algorithm", kind: .invalidAlgorithm)
        }
        
        var error: Unmanaged<CFError>?
        guard SecKeyVerifySignature(publicKey,
                                    .ecdsaSignatureMessageX962SHA256,
                                    data as CFData,
                                    signature as CFData,
                                    &error) else {
            let printableError = error!.takeRetainedValue() as Error
            print(printableError)
            return false
        }
        return true
    }
}
