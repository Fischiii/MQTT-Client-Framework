//
//  MQTTCFSocketTransport.m
//  MQTTClient
//
//  Created by Christoph Krey on 06.12.15.
//  Copyright © 2015-2017 Christoph Krey. All rights reserved.
//

#import "MQTTCFSocketTransport.h"

#import "MQTTLog.h"

@interface MQTTCFSocketTransport() {
    void *QueueIdentityKey;
}

@property (strong, nonatomic) MQTTCFSocketEncoder *encoder;
@property (strong, nonatomic) MQTTCFSocketDecoder *decoder;

@end

@implementation MQTTCFSocketTransport

@synthesize state;
@synthesize delegate;
@synthesize queue = _queue;
@synthesize streamSSLLevel;
@synthesize host;
@synthesize port;

- (instancetype)init {
    self = [super init];
    self.host = @"localhost";
    self.port = 1883;
    self.tls = false;
    self.allowsCellularAccess = YES;
    self.voip = false;
    self.certificates = nil;
    self.queue = dispatch_get_main_queue();
    self.streamSSLLevel = (NSString *)kCFStreamSocketSecurityLevelNegotiatedSSL;
    return self;
}

- (void)dealloc {
    [self close];
}

- (void)setQueue:(dispatch_queue_t)queue {
    _queue = queue;
    
    // We're going to use dispatch_queue_set_specific() to "mark" our queue.
    // The dispatch_queue_set_specific() and dispatch_get_specific() functions take a "void *key" parameter.
    // Later we can use dispatch_get_specific() to determine if we're executing on our queue.
    // From the documentation:
    //
    // > Keys are only compared as pointers and are never dereferenced.
    // > Thus, you can use a pointer to a static variable for a specific subsystem or
    // > any other value that allows you to identify the value uniquely.
    //
    // So we're just going to use the memory address of an ivar.
    
    dispatch_queue_set_specific(_queue, &QueueIdentityKey, (__bridge void *)_queue, NULL);
}

- (BOOL)evaluateTrustChain: (SecTrustRef)serverTrust {
    
    // Create a custom trust evaluation policy
    SecCertificateRef certificate = self.certificatePin;
    CFArrayRef caArray = CFArrayCreate(NULL, (const void **)&certificate, 1, &kCFTypeArrayCallBacks);
    SecTrustSetAnchorCertificates(serverTrust, caArray);
    SecTrustSetAnchorCertificatesOnly(serverTrust, YES); // Only trust the provided CA

      // Evaluate the server's certificate
     // Evaluate the server certificate
     CFErrorRef error = NULL;
     BOOL trusted = SecTrustEvaluateWithError(serverTrust, &error);

     // Release the CA array
     CFRelease(caArray);

     if (trusted) {
         // The certificate is trusted
         return trusted;
     } else {
         // Handle the error if needed
         if (error) {
             CFStringRef errorDescription = CFErrorCopyDescription(error);
             NSLog(@"Trust evaluation failed: %@", errorDescription);
             CFRelease(errorDescription);
             CFRelease(error);
         }
     }
    return NO;
}

void customStreamCallback(CFReadStreamRef stream, CFStreamEventType type, void *clientCallBackInfo) {
    if (type == kCFStreamEventHasBytesAvailable || type == kCFStreamEventCanAcceptBytes) {
        // Obtain the server trust
        SecTrustRef serverTrust = (SecTrustRef)CFReadStreamCopyProperty(stream, kCFStreamPropertySSLPeerTrust);
        if (serverTrust) {
            
            // Create a custom trust evaluation policy
            if ([((__bridge MQTTCFSocketTransport *)clientCallBackInfo) evaluateTrustChain:serverTrust]){
                CFRelease(serverTrust);
                return;
            }
          
            CFRelease(serverTrust);
        }

        // If trust evaluation fails, close the stream
        CFReadStreamClose(stream);
    } else if (type == kCFStreamEventErrorOccurred) {
        // Handle the error
        CFReadStreamClose(stream);
    }
}

void customWriteStreamCallback(CFWriteStreamRef stream, CFStreamEventType type, void *clientCallBackInfo) {
    if (type == kCFStreamEventHasBytesAvailable || type == kCFStreamEventCanAcceptBytes) {
        // Obtain the server trust
        SecTrustRef serverTrust = (SecTrustRef)CFWriteStreamCopyProperty(stream, kCFStreamPropertySSLPeerTrust);
        if (serverTrust) {
           
            
            // Create a custom trust evaluation policy
            if ([((__bridge MQTTCFSocketTransport *)clientCallBackInfo) evaluateTrustChain:serverTrust]){
                CFRelease(serverTrust);
                return;
            }
            
            CFRelease(serverTrust);
        }

        // If trust evaluation fails, close the stream
        CFWriteStreamClose(stream);
    } else if (type == kCFStreamEventErrorOccurred) {
        // Handle the error
        CFWriteStreamClose(stream);
    }
}

- (void)open {
    DDLogVerbose(@"[MQTTCFSocketTransport] open");
    self.state = MQTTTransportOpening;

    NSError* connectError;

    CFReadStreamRef readStream;
    CFWriteStreamRef writeStream;

    CFStreamCreatePairWithSocketToHost(NULL, (__bridge CFStringRef)self.host, self.port, &readStream, &writeStream);

    CFReadStreamSetProperty(readStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanTrue);
    CFWriteStreamSetProperty(writeStream, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanTrue);
    
    if (self.tls) {
        NSMutableDictionary *sslOptions = [[NSMutableDictionary alloc] init];
        
        sslOptions[(NSString *)kCFStreamSSLLevel] = self.streamSSLLevel;
        
        if (self.certificates) {
            sslOptions[(NSString *)kCFStreamSSLCertificates] = self.certificates;
        }
        
        if(self.certificatePin){
            // Disable default certificate validation

            sslOptions[(NSString *)kCFStreamSSLValidatesCertificateChain] = @NO;
            
            // Add a custom SSL trust callback
            CFReadStreamSetClient(readStream, kCFStreamEventHasBytesAvailable | kCFStreamEventErrorOccurred, customStreamCallback, NULL);
            // Write stream needs a different CB
            CFWriteStreamSetClient(writeStream, kCFStreamEventCanAcceptBytes | kCFStreamEventErrorOccurred, customWriteStreamCallback, NULL);

        }
        
        if (!CFReadStreamSetProperty(readStream, kCFStreamPropertySSLSettings, (__bridge CFDictionaryRef)(sslOptions))) {
            connectError = [NSError errorWithDomain:@"MQTT"
                                               code:errSSLInternal
                                           userInfo:@{NSLocalizedDescriptionKey : @"Fail to init ssl input stream!"}];
        }
        if (!CFWriteStreamSetProperty(writeStream, kCFStreamPropertySSLSettings, (__bridge CFDictionaryRef)(sslOptions))) {
            connectError = [NSError errorWithDomain:@"MQTT"
                                               code:errSSLInternal
                                           userInfo:@{NSLocalizedDescriptionKey : @"Fail to init ssl output stream!"}];
        }
    }
    
    if (!self.allowsCellularAccess) {
        CFReadStreamSetProperty(readStream, kCFStreamPropertyNoCellular, kCFBooleanTrue);
        CFWriteStreamSetProperty(writeStream, kCFStreamPropertyNoCellular, kCFBooleanTrue);
    }
    
    if (!connectError) {
        self.encoder.delegate = nil;
        self.encoder = [[MQTTCFSocketEncoder alloc] init];
        CFWriteStreamSetDispatchQueue(writeStream, self.queue);
        self.encoder.stream = CFBridgingRelease(writeStream);
        self.encoder.delegate = self;
        if (self.voip) {
            [self.encoder.stream setProperty:NSStreamNetworkServiceTypeVoIP forKey:NSStreamNetworkServiceType];
        }
        [self.encoder open];
        
        self.decoder.delegate = nil;
        self.decoder = [[MQTTCFSocketDecoder alloc] init];
        CFReadStreamSetDispatchQueue(readStream, self.queue);
        self.decoder.stream =  CFBridgingRelease(readStream);
        self.decoder.delegate = self;
        if (self.voip) {
            [self.decoder.stream setProperty:NSStreamNetworkServiceTypeVoIP forKey:NSStreamNetworkServiceType];
        }
        [self.decoder open];
    } else {
        [self close];
    }
}

- (void)close {
    // https://github.com/novastone-media/MQTT-Client-Framework/issues/325
    // We need to make sure that we are closing streams on their queue
    // Otherwise, we end up with race condition where delegate is deallocated
    // but still used by run loop event
    if (self.queue != dispatch_get_specific(&QueueIdentityKey)) {
        dispatch_sync(self.queue, ^{
            [self internalClose];
        });
    } else {
        [self internalClose];
    }
}

- (void)internalClose {
    DDLogVerbose(@"[MQTTCFSocketTransport] close");
    self.state = MQTTTransportClosing;

    if (self.encoder) {
        [self.encoder close];
        self.encoder.delegate = nil;
    }
    
    if (self.decoder) {
        [self.decoder close];
        self.decoder.delegate = nil;
    }
}

- (BOOL)send:(nonnull NSData *)data {
    return [self.encoder send:data];
}

- (void)decoder:(MQTTCFSocketDecoder *)sender didReceiveMessage:(nonnull NSData *)data {
    [self.delegate mqttTransport:self didReceiveMessage:data];
}

- (void)decoder:(MQTTCFSocketDecoder *)sender didFailWithError:(NSError *)error {
    //self.state = MQTTTransportClosing;
    //[self.delegate mqttTransport:self didFailWithError:error];
}
- (void)encoder:(MQTTCFSocketEncoder *)sender didFailWithError:(NSError *)error {
    self.state = MQTTTransportClosing;
    [self.delegate mqttTransport:self didFailWithError:error];
}

- (void)decoderdidClose:(MQTTCFSocketDecoder *)sender {
    self.state = MQTTTransportClosed;
    [self.delegate mqttTransportDidClose:self];
}
- (void)encoderdidClose:(MQTTCFSocketEncoder *)sender {
    //self.state = MQTTTransportClosed;
    //[self.delegate mqttTransportDidClose:self];
}

- (void)decoderDidOpen:(MQTTCFSocketDecoder *)sender {
    //self.state = MQTTTransportOpen;
    //[self.delegate mqttTransportDidOpen:self];
}
- (void)encoderDidOpen:(MQTTCFSocketEncoder *)sender {
    self.state = MQTTTransportOpen;
    [self.delegate mqttTransportDidOpen:self];
}

+ (NSArray *)clientCertsFromP12:(NSString *)path passphrase:(NSString *)passphrase {
    if (!path) {
        DDLogWarn(@"[MQTTCFSocketTransport] no p12 path given");
        return nil;
    }
    
    NSData *pkcs12data = [[NSData alloc] initWithContentsOfFile:path];
    if (!pkcs12data) {
        DDLogWarn(@"[MQTTCFSocketTransport] reading p12 failed");
        return nil;
    }
    
    if (!passphrase) {
        DDLogWarn(@"[MQTTCFSocketTransport] no passphrase given");
        return nil;
    }
    CFArrayRef keyref = NULL;
    OSStatus importStatus = SecPKCS12Import((__bridge CFDataRef)pkcs12data,
                                            (__bridge CFDictionaryRef)@{(__bridge id)kSecImportExportPassphrase: passphrase},
                                            &keyref);
    if (importStatus != noErr) {
        DDLogWarn(@"[MQTTCFSocketTransport] Error while importing pkcs12 [%d]", (int)importStatus);
        return nil;
    }
    
    CFDictionaryRef identityDict = (CFDictionaryRef)CFArrayGetValueAtIndex(keyref, 0);
    if (!identityDict) {
        DDLogWarn(@"[MQTTCFSocketTransport] could not CFArrayGetValueAtIndex");
        return nil;
    }
    
    SecIdentityRef identityRef = (SecIdentityRef)CFDictionaryGetValue(identityDict,
                                                                      kSecImportItemIdentity);
    if (!identityRef) {
        DDLogWarn(@"[MQTTCFSocketTransport] could not CFDictionaryGetValue");
        return nil;
    };
    
    SecCertificateRef cert = NULL;
    OSStatus status = SecIdentityCopyCertificate(identityRef, &cert);
    if (status != noErr) {
        DDLogWarn(@"[MQTTCFSocketTransport] SecIdentityCopyCertificate failed [%d]", (int)status);
        return nil;
    }
    
    NSArray *clientCerts = @[(__bridge id)identityRef, (__bridge id)cert];
    return clientCerts;
}

@end
