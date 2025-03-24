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
        let pubKey = asymKeyPair.getPublicKey()
        
        // Use this local authentication context to bypass Apple prompt when using the cryptographic key
        //let context = LAContext()
        //context.setCredential("password".data(using: .utf8), type: .applicationPassword)
        //let retrievedKey = asymKeyPair.retrieveKey(context: context)
        let retrievedKey = asymKeyPair.retrieveKey()

        var signedMessage: Data?
        try! signedMessage = asymKeyPair.sign(data: "abc", key: retrievedKey!)
        print(signedMessage?.base64EncodedString())
    }
}
