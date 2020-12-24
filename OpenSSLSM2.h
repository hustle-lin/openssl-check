//
//  OpenSSLSM2.h
//  Pods
//
//  Created by NBig on 2019/12/3.
//

#import <Foundation/Foundation.h>

 
@interface OpenSSLSM2 : NSObject

+ (NSString *)decodeWithDer:(NSString *)derSign;

+ (BOOL)verify:(NSString *)plainStr signRS:(NSString *)signRS pubKey:(NSString *)pubKey uid:(NSString *)uid;

@end

 
