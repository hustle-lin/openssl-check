//
//  OpenSSLSM2.m
//  Pods
//
//  Created by NBig on 2019/12/3.
//

#import "OpenSSLSM2.h"

#import <openssl/sm2.h>
#import <openssl/evp.h>
#import <openssl/bn.h>
#import <openssl/asn1.h>



@implementation OpenSSLSM2

+ (nullable NSString *)decodeWithDer:(NSString *)derSign
{
    if (derSign.length == 0) {
        return nil;
    }
    const char *sign_hex = derSign.UTF8String;
    long sign_len = 0;
    uint8_t *sign_buffer = OPENSSL_hexstr2buf(sign_hex, &sign_len);
    const uint8_t *sign_char = sign_buffer;
    // 复制一份，对比验证
    long sign_copy_len = 0;
    uint8_t *sign_copy = OPENSSL_hexstr2buf(sign_hex, &sign_copy_len);
    
    ECDSA_SIG *sig = NULL;
    const BIGNUM *sig_r = NULL;
    const BIGNUM *sig_s = NULL;
    unsigned char *der = NULL;
    int derlen = -1;
    
    NSString *originSign = nil;
    
    do {
        sig = ECDSA_SIG_new();
        if (sig == NULL) {
            break;
        }
        if (d2i_ECDSA_SIG(&sig, &sign_char, sign_len) == NULL) {
            break;
        }
        /* Ensure signature uses DER and doesn't have trailing garbage */
        derlen = i2d_ECDSA_SIG(sig, &der);
        if (derlen != sign_len || memcmp(sign_copy, der, derlen) != 0) {
            break;
        }
        // 取出 r, s
        ECDSA_SIG_get0(sig, &sig_r, &sig_s);
        char *r_hex = BN_bn2hex(sig_r);
        char *s_hex = BN_bn2hex(sig_s);
        NSString *rStr = [NSString stringWithCString:r_hex encoding:NSUTF8StringEncoding];
        NSString *sStr = [NSString stringWithCString:s_hex encoding:NSUTF8StringEncoding];
        OPENSSL_free(r_hex);
        OPENSSL_free(s_hex);
        if (rStr.length == 0 || sStr.length == 0) {
            break;
        }
        originSign = [NSString stringWithFormat:@"%@,%@", rStr, sStr];
    } while (NO);
    
    ECDSA_SIG_free(sig);
    OPENSSL_free(der);
    OPENSSL_free(sign_buffer);
    OPENSSL_free(sign_copy);
    
    return originSign;
}

+ (BOOL)verify:(NSString *)plainStr signRS:(NSString *)signRS pubKey:(NSString *)pubKey uid:(NSString *)uid{

    NSData *plainData = [plainStr dataUsingEncoding:NSUTF8StringEncoding];
    NSData *userData = [uid dataUsingEncoding:NSUTF8StringEncoding];
    
    const char *pub_key = pubKey.UTF8String;
    uint8_t *plain_bytes = (uint8_t *)plainData.bytes;
    size_t plain_len = plainData.length;
    uint8_t *user_id = (uint8_t *)userData.bytes;
    size_t user_len = userData.length;
    
    NSArray<NSString *> *rsArray = [signRS componentsSeparatedByString:@","];
    if (rsArray.count < 2) return NO;
    
    NSString *r_hex = rsArray[0];
    NSString *s_hex = rsArray[1];
    
    ECDSA_SIG *sig = NULL;  // 签名结果
    BIGNUM *sig_r = NULL;
    BIGNUM *sig_s = NULL;
    const EVP_MD *digest = EVP_sm3();  // 摘要算法
    EC_POINT *pub_point = NULL;  // 公钥坐标
    EC_KEY *key = NULL;  // 密钥key
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    BOOL isOK = NO;  // 验签结果
    
    do {
        if (!BN_hex2bn(&sig_r, r_hex.UTF8String)) {
            break;
        }
        if (!BN_hex2bn(&sig_s, s_hex.UTF8String)) {
            break;
        }
        sig = ECDSA_SIG_new();
        if (sig == NULL) {
            BN_free(sig_r);
            BN_free(sig_s);
            break;
        }
        if (!ECDSA_SIG_set0(sig, sig_r, sig_s)) {
            break;
        }
        key = EC_KEY_new();
        if (!EC_KEY_set_group(key, group)) {
            break;
        }
        pub_point = EC_POINT_new(group);
        EC_POINT_hex2point(group, pub_key, pub_point, NULL);
        if (!EC_KEY_set_public_key(key, pub_point)) {
            break;
        }
        int ok = sm2_do_verify(key, digest, sig, user_id, user_len, plain_bytes, plain_len);
        isOK = ok > 0 ? YES : NO;
    } while (NO);
    
    EC_POINT_free(pub_point);
    EC_KEY_free(key);
    ECDSA_SIG_free(sig);
    if (group != NULL){
        EC_GROUP_free(group);
    }
    
    return isOK;
}

@end
