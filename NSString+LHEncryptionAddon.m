//
//  NSString+LHEncryptionAddon.m
//  CoinOKWallet
//
//  Created by okcoin on 14-8-18.
//  Copyright (c) 2014年 OkCoin. All rights reserved.
//

#import "NSString+LHEncryptionAddon.h"
#import <CommonCrypto/CommonDigest.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>

#import "RSA.h"

@implementation NSString (LHEncryptionAddon)

#pragma mark - 16位MD5加密方式 : 提取32位MD5散列的中间16位
+ (NSString *)getMd5_16Bit_String:(NSString *)srcString{
    NSString *md5_32Bit_String=[self getMd5_32Bit_String:srcString];
    NSString *result = [[md5_32Bit_String substringToIndex:24] substringFromIndex:8];//即9～25位
    
    return result;
}

#pragma mark - 32位MD5加密方式
+ (NSString *)getMd5_32Bit_String:(NSString *)srcString{
    const char *cStr = [srcString UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5( cStr, strlen(cStr), digest );
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [result appendFormat:@"%02x", digest[i]];
    
    return result;
}

#pragma mark - sha1加密方式
+ (NSString *)getSha1String:(NSString *)srcString{
    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
    
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    
    CC_SHA1(data.bytes, data.length, digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    return result;
}

#pragma mark - sha256加密方式
+ (NSString *)getSha256String:(NSString *)srcString {
    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
    
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    
    CC_SHA1(data.bytes, data.length, digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    return result;
}

#pragma mark - sha384加密方式
+ (NSString *)getSha384String:(NSString *)srcString {
    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
    
    uint8_t digest[CC_SHA384_DIGEST_LENGTH];
    
    CC_SHA1(data.bytes, data.length, digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA384_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA384_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    
    return result;
}

#pragma mark - sha512加密方式
+ (NSString*) getSha512String:(NSString*)srcString {
    const char *cstr = [srcString cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:srcString.length];
    uint8_t digest[CC_SHA512_DIGEST_LENGTH];
    
    CC_SHA512(data.bytes, data.length, digest);
    
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_SHA512_DIGEST_LENGTH; i++)
        [result appendFormat:@"%02x", digest[i]];
    return result;
}

#pragma mark - 邮箱加密方式
+ (NSString*) getEncryptionEmailString:(NSString*)emailString{
    if ([emailString length] <= 0) {
        return @"";
    }
    NSString * encryptionString = nil;
    NSRange range = [emailString rangeOfString:@"@"];
    if (range.location != NSNotFound) {
        encryptionString = [emailString stringByReplacingCharactersInRange:NSMakeRange(range.location > 3 ? 3 : (range.location - 1), range.location - (range.location > 3 ? 3 : (range.location - 1))) withString:@"***"];
    }else{
        encryptionString = @"***";
    }
    return encryptionString;
}

#pragma mark - 电话号码加密方式
+ (NSString*) getEncryptionPhoneNumString:(NSString *)phoneNumString{
    if ([phoneNumString length] <= 0) {
        return @"";
    }
    NSString * encryptionString = nil;
    encryptionString = [phoneNumString stringByReplacingCharactersInRange:[phoneNumString length] > 3 ? NSMakeRange(3, 4) : NSMakeRange([phoneNumString length] - 1, 1) withString:@"****"];
    return encryptionString;
}

#pragma mark - 身份证号加密方式
+ (NSString*) getEncryptionIDnumberString:(NSString *)IDnumberString{
    if ([IDnumberString length] < 6) {
        return @"";
    }
    NSString * encryptionString = nil;
    encryptionString = [IDnumberString stringByReplacingCharactersInRange:NSMakeRange([IDnumberString length] == 15 ? 8 : [IDnumberString length] == 18 ? 10 : 1, 4) withString:@"****"];
    return encryptionString;
}

@end
