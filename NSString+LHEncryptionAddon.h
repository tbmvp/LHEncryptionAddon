//
//  NSString+LHEncryptionAddon.h
//  CoinOKWallet
//
//  Created by okcoin on 14-8-18.
//  Copyright (c) 2014年 OkCoin. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef void (^RSASuccessBlock)(BOOL *success, id responseObject);

@interface NSString (LHEncryptionAddon)

#pragma mark - 16位MD5加密方式 : 提取32位MD5散列的中间16位
+ (NSString*) getMd5_16Bit_String:(NSString *)srcString;

#pragma mark - 32位MD5加密方式
+ (NSString*) getMd5_32Bit_String:(NSString *)srcString;

#pragma mark - sha1加密方式
+ (NSString*) getSha1String:(NSString *)srcString;

#pragma mark - sha256加密方式
+ (NSString*) getSha256String:(NSString *)srcString;

#pragma mark - sha384加密方式
+ (NSString*)getSha384String:(NSString *)srcString;

#pragma mark - sha512加密方式
+ (NSString*) getSha512String:(NSString*)srcString;

#pragma mark - 邮箱加密方式
+ (NSString*) getEncryptionEmailString:(NSString*)emailString;

#pragma mark - 电话号码加密方式
+ (NSString*) getEncryptionPhoneNumString:(NSString *)phoneNumString;

#pragma mark - 身份证号加密方式
+ (NSString*) getEncryptionIDnumberString:(NSString *)IDnumberString;

@end
