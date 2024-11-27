//
//  MQTTCFVerify.m
//  MQTTClient
//
//  Created by Arne Fischer on 27.11.24.
//  Copyright © 2024 Christoph Krey. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MQTTCFVerify.h"
#import "MQTTLog.h"


@implementation MQTTCFVerify


+ (BOOL)evaluateTrustChain: (SecTrustRef)serverTrust certificate:(SecCertificateRef)certificate {
    DDLogVerbose(@"[MQTTCFVerify] evaluateTrustChain");
   
    // The certificate
    NSArray *caArray = @[(__bridge id)certificate];
    OSStatus status = SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)caArray);
    if (status != errSecSuccess) {
           DDLogError(@"[MQTTCFVerify] Failed to set anchor certificates: %d", (int)status);
           return NO;
    }

    // disabel additional system certificate to actually pin the provided certificate
    SecTrustSetAnchorCertificatesOnly(serverTrust, YES);

    // set the policy to do starndard x509 checking
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    status = SecTrustSetPolicies(serverTrust, policy);
    if (status != errSecSuccess) {
           DDLogError(@"[MQTTCFVerify] Failed to set trust policy: %d", (int)status);
           return NO;
    }
    
    // The actual evaluation of servere trust
    CFErrorRef error = NULL;
    BOOL trusted = SecTrustEvaluateWithError(serverTrust, &error);

    CFRelease(policy);
    if (trusted) {
        // The certificate is trusted
        return trusted;
    } else {
        // Handle the error if needed
        if (error) {
            CFStringRef errorDescription = CFErrorCopyDescription(error);
            DDLogError(@"[MQTTCFVerify] Trust evaluation failed: %@", errorDescription);
            CFRelease(errorDescription);
            CFRelease(error);
        }
    }
    // trust failed
    return NO;
}

+ (void)checkSSLTrustForWriteStream:(CFWriteStreamRef)stream certificate:(SecCertificateRef)certificate {
    DDLogVerbose(@"[MQTTCFVerify] checkSSLTrustForWriteStream");
   
    // Obtain the server trust
    CFStreamStatus status = CFWriteStreamGetStatus(stream);
    DDLogVerbose(@"[MQTTCFVerify] write stream status %li", (long)status);
    
    SecTrustRef serverTrust = (SecTrustRef)CFWriteStreamCopyProperty(stream, kCFStreamPropertySSLPeerTrust);
    if (serverTrust) {
        
        if ([MQTTCFVerify evaluateTrustChain:serverTrust certificate:certificate]){
            DDLogVerbose(@"[MQTTCFVerify] trust write stream");
            CFRelease(serverTrust);
            return;
        }
        
        CFRelease(serverTrust);
    }
    
    // If trust evaluation fails, close the stream
    CFWriteStreamClose(stream);
}


+ (void)checkSSLTrustForReadStream:(CFReadStreamRef)stream certificate:(SecCertificateRef)certificate {
    DDLogVerbose(@"[MQTTCFVerify] checkSSLTrustForReadStream");
   
    // Obtain the server trust
    CFStreamStatus status = CFReadStreamGetStatus(stream);
    DDLogVerbose(@"[MQTTCFVerify] read stream status %li", (long)status);

    SecTrustRef serverTrust = (SecTrustRef)CFReadStreamCopyProperty(stream, kCFStreamPropertySSLPeerTrust);
    if (serverTrust) {
        
        if ([MQTTCFVerify evaluateTrustChain:serverTrust certificate:certificate]){
            DDLogVerbose(@"[MQTTCFVerify] trust read stream");
            CFRelease(serverTrust);
            return;
        }
        
        CFRelease(serverTrust);
    }
    
    // If trust evaluation fails, close the stream
    CFReadStreamClose(stream);
}

@end

