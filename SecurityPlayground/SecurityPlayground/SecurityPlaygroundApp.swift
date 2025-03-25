//
//  SecurityPlaygroundApp.swift
//  SecurityPlayground
//
//  Created by Guillaume Bohr on 21/03/2025.
//

import SwiftUI
import LocalAuthentication

@main
struct SecurityPlaygroundApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .onAppear(perform: testCrypto)
        }
    }
    
    func testCrypto() {
        let asymKeyPair = AsymetricKeyPairProvider()
        
        // Use this local authentication context to bypass Apple prompt when using the cryptographic key
        let context = LAContext()
        context.setCredential("password".data(using: .utf8), type: .applicationPassword)
        
        for _ in 0...5 {
            // Pass a nil context to force Apple password prompt
            testSignature(keyPair: asymKeyPair, message: "message", context: context)
        }
    }
    
    func testSignature(keyPair: AsymetricKeyPairProvider, message: String, context: LAContext? = nil) {
        let messageData = message.data(using: .utf8)!
        let privateKey = keyPair.getPrivateKey(context: context)!
        let publicKey = keyPair.getPublicKey()
        var signature: Data
        try! signature = keyPair.sign(data: messageData, privateKey: privateKey)!
        print(signature.base64EncodedString())
        var isVerified: Bool
        try! isVerified = keyPair.verify(data: messageData, publicKey: publicKey, signature: signature)
        print(isVerified)
    }
}
