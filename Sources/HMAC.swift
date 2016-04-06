//
//  HMAC.swift
//  CryptoSwift
//
//  Created by Marcin Krzyzanowski on 13/01/15.
//  Copyright (c) 2015 Marcin Krzyzanowski. All rights reserved.
//

import CryptoEssentials

final public class HMAC<Variant: HashProtocol> {
    var key: [UInt8]
    
    class public func authenticate(key  key: [UInt8], message: [UInt8], variant: Variant.Type) -> [UInt8] {
        return HMAC<Variant>(key).authenticate(message: message)
    }
    
    // MARK: - Private
    
    public init (_ key: [UInt8]) {
        self.key = key
        
        let hashingVariant = Variant(key)
        
        if (key.count > 64) {
            self.key = hashingVariant.calculate()
        }
        
        if (key.count < 64) { // keys shorter than blocksize are zero-padded
            self.key = key + [UInt8](repeating: 0, count: 64 - key.count)
        }
    }
    
    public func authenticate(message message: [UInt8]) -> [UInt8] {
        var opad = [UInt8](repeating: 0x5c, count: 64)
        for (idx, _) in key.enumerated() {
            opad[idx] = key[idx] ^ opad[idx]
        }
        var ipad = [UInt8](repeating: 0x36, count: 64)
        for (idx, _) in key.enumerated() {
            ipad[idx] = key[idx] ^ ipad[idx]
        }

        let hashingVariant = Variant(ipad + message)

        let ipadAndMessageHash = hashingVariant.calculate()
        let finalHashingVariant = Variant(opad + ipadAndMessageHash)
        let finalHash = finalHashingVariant.calculate();
        
        return finalHash
    }
}