//
//  ContentView.swift
//  SecurityPlayground
//
//  Created by Guillaume Bohr on 21/03/2025.
//

import SwiftUI

struct ContentView: View {
    let asymKeyPair = AsymetricKeyPairProvider()
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text("Hello, world!")
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
