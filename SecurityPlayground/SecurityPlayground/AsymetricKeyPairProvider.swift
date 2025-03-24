//
//  AsymetricKeyPairProvider.swift
//  SecurityPlayground
//
//  Created by Guillaume Bohr on 21/03/2025.
//

import Foundation
import LocalAuthentication

struct AsymetricKeyPairProvider: Any {
    let secKeyAttrLabel = "com.bohrgu.secpg.asymkeypair.secureenclave.label"
    let secKeyAttrTag = "com.bohrgu.secpg.asymkeypair.secureenclave.tag"
    let privateKeyRef: SecKey?
    
    init() {
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
            kSecAttrLabel: secKeyAttrLabel,
            kSecClass: kSecClassKey,
            kSecUseAuthenticationContext: context,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: secKeyAttrTag,
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
    
    func getPublicKey() -> SecKey {
        return SecKeyCopyPublicKey(self.privateKeyRef!)!
    }
    
    func retrieveKey(context: LAContext? = nil) -> SecKey? {
        var attributes: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: secKeyAttrLabel,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnRef as String: true,
        ]
        
        if let context = context {
            attributes[kSecUseAuthenticationContext as String] = context
        }
        
        var item: CFTypeRef?
        let res = SecItemCopyMatching(attributes as CFDictionary, &item)
        
        if (res == errSecSuccess) {
            return (item as! SecKey)
        } else {
            return nil
        }
    }
    
    func sign(data: String, key: SecKey) throws -> Data? {
        if (SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256)) {
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(key,
                                                        .ecdsaSignatureMessageX962SHA256,
                                                        data.data(using: .utf8)! as CFData,
                                                        &error) as Data? else {
                throw error!.takeRetainedValue() as Error
            }
            return signature
        }
        return nil
    }
}
