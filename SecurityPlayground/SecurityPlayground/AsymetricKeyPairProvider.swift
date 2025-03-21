//
//  AsymetricKeyPairProvider.swift
//  SecurityPlayground
//
//  Created by Guillaume Bohr on 21/03/2025.
//

import Foundation
import LocalAuthentication

struct AsymetricKeyPairProvider: Any {
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
            kSecAttrLabel: "com.bohrgu.secpg.asymkeypair.secureenclave.label",
            kSecClass: kSecClassKey,
            kSecUseAuthenticationContext: context,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: "com.bohrgu.secpg.asymkeypair.secureenclave.tag",
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
}
