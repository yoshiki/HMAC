//
//  HMAC.swift
//  CryptoSwift
//
//  Created by Marcin Krzyzanowski on 13/01/15.
//  Copyright (c) 2015 Marcin Krzyzanowski. All rights reserved.
//

import CryptoEssentials

final public class HMAC {
    var key: [UInt8]
    let variant: HashProtocol.Type
    
    class public func authenticate(key  key: [UInt8], message: [UInt8], variant: HashProtocol.Type) -> [UInt8]? {
        return HMAC(key, variant: variant)?.authenticate(message: message)
    }
    
    // MARK: - Private
    
    public init? (_ key: [UInt8], variant: HashProtocol.Type) {
        self.variant = variant
        self.key = key
        
        let hashingVariant = variant.init(key)
        
        if (key.count > 64) {
            self.key = hashingVariant.calculate()
        }
        
        if (key.count < 64) { // keys shorter than blocksize are zero-padded
            self.key = key + [UInt8](repeating: 0, count: 64 - key.count)
        }
    }
    
    public func authenticate(message  message:[UInt8]) -> [UInt8]? {
        var opad = [UInt8](repeating: 0x5c, count: 64)
        for (idx, _) in key.enumerated() {
            opad[idx] = key[idx] ^ opad[idx]
        }
        var ipad = [UInt8](repeating: 0x36, count: 64)
        for (idx, _) in key.enumerated() {
            ipad[idx] = key[idx] ^ ipad[idx]
        }
        
        let hashingVariant = variant.init(ipad + message)

        var finalHash:[UInt8]? = nil;
        let ipadAndMessageHash = hashingVariant.calculate()
        let finalHashingVariant = variant.init(opad + ipadAndMessageHash)
        finalHash = finalHashingVariant.calculate();
        
        return finalHash
    }
}