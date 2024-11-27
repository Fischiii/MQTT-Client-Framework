//
//  MQTTCFVerify.h
//  MQTTClient
//
//  Created by Arne Fischer on 27.11.24.
//  Copyright © 2024 Arne Fischer. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface MQTTCFVerify : NSObject
/**
 * Used if certificate is pinned to verify that the certificate provided by the serve is trusted.
 */
+ (void) checkSSLTrustForReadStream:(CFReadStreamRef) stream certificate:(SecCertificateRef) certificate;

/**
 * Used if certificate is pinned to verify that the certificate provided by the serve is trusted.
 */
+ (void) checkSSLTrustForWriteStream:(CFWriteStreamRef) stream certificate:(SecCertificateRef) certificate;

@end
