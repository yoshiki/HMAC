//
//  HMAC.swift
//  CryptoSwift
//
//  Created by Marcin Krzyzanowski on 13/01/15.
//  Copyright (c) 2015 Marcin Krzyzanowski. All rights reserved.
//

import CryptoEssentials

final public class HMAC {
    public static func authenticate(message:[Byte], withKey key: [Byte], using variant: HashProtocol.Type) -> [Byte] {
        var key = key
        
        if (key.count > 64) {
            key = variant.calculate(key)
        }
        
        if (key.count < 64) { // keys shorter than blocksize are zero-padded
            key = key + [UInt8](repeating: 0, count: 64 - key.count)
        }
        
        var opad = [Byte](repeating: 0x5c, count: 64)
        for (idx, _) in key.enumerated() {
            opad[idx] = key[idx] ^ opad[idx]
        }
        var ipad = [Byte](repeating: 0x36, count: 64)
        for (idx, _) in key.enumerated() {
            ipad[idx] = key[idx] ^ ipad[idx]
        }
        
        let ipadAndMessageHash = variant.calculate(ipad + message)
        let finalHash = variant.calculate(opad + ipadAndMessageHash);
        
        return finalHash
    }
}