//
//  NSData+AES.h
//  OralEduManager
//
//  Created by lihao_en on 14-7-28.
//  Copyright (c) 2014年 com.oral_edu. All rights reserved.
//

#import <Foundation/Foundation.h>

@class NSString;

@interface NSData (AES)

- (NSData *)AESEncryptWithKey:(NSString *)key;
- (NSData *)AESDecryptWithKey:(NSString *)key;

@end
