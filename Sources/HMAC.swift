//
//  HMAC.swift
//  CryptoSwift
//
//  Created by Marcin Krzyzanowski on 13/01/15.
//  Copyright (c) 2015 Marcin Krzyzanowski. All rights reserved.
//

import CryptoEssentials

final public class HMAC<Variant: HashProtocol> {
    public static func authenticate(message:[Byte], withKey key: [Byte]) -> [Byte] {
        var key = key
        
        if (key.count > Variant.size) {
            key = Variant.calculate(key)
        }
        
        if (key.count < Variant.size) { // keys shorter than blocksize are zero-padded
            key = key + [UInt8](repeating: 0, count: Variant.size - key.count)
        }
        
        var opad = [Byte](repeating: 0x5c, count: Variant.size)
        for (idx, _) in key.enumerated() {
            opad[idx] = key[idx] ^ opad[idx]
        }
        var ipad = [Byte](repeating: 0x36, count: Variant.size)
        for (idx, _) in key.enumerated() {
            ipad[idx] = key[idx] ^ ipad[idx]
        }
        
        let ipadAndMessageHash = Variant.calculate(ipad + message)
        let finalHash = Variant.calculate(opad + ipadAndMessageHash);
        
        return finalHash
    }
}