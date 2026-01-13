#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <objc/runtime.h>
#include "fishhook.h"

// --- Configuration ---
static NSString *const kCustomIDFVKey = @"kMyCustomIDFV";
static NSString *const kCustomIDFAKey = @"kMyCustomIDFA";

// --- Helper Functions ---

static NSString *GenerateRandomUUID() {
    return [[NSUUID UUID] UUIDString];
}

static NSString *GetStoredID(NSString *key) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *val = [defaults stringForKey:key];
    if (!val) {
        val = GenerateRandomUUID();
        [defaults setObject:val forKey:key];
        [defaults synchronize];
    }
    return val;
}

static void RotateIDs() {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:GenerateRandomUUID() forKey:kCustomIDFVKey];
    [defaults setObject:GenerateRandomUUID() forKey:kCustomIDFAKey];
    [defaults synchronize];
    NSLog(@"[DeviceRotator] IDs Rotated!");
}

// --- Hooking IDFV (UIDevice) ---

// Original implementation method pointer (not strictly needed for pure swizzling replacement but good practice)
// In this simple case, we just replace the method to return our string.

@interface UIDevice (Hook)
- (NSUUID *)swizzled_identifierForVendor;
@end

@implementation UIDevice (Hook)
- (NSUUID *)swizzled_identifierForVendor {
    NSString *uuidStr = GetStoredID(kCustomIDFVKey);
    // NSLog(@"[DeviceRotator] Hooked IDFV: %@", uuidStr);
    return [[NSUUID alloc] initWithUUIDString:uuidStr];
}
@end

// --- Hooking IDFA (ASIdentifierManager) ---

@interface ASIdentifierManager (Hook)
- (NSUUID *)swizzled_advertisingIdentifier;
@end

@implementation ASIdentifierManager (Hook)
- (NSUUID *)swizzled_advertisingIdentifier {
    NSString *uuidStr = GetStoredID(kCustomIDFAKey);
    // NSLog(@"[DeviceRotator] Hooked IDFA: %@", uuidStr);
    return [[NSUUID alloc] initWithUUIDString:uuidStr];
}
@end


// --- Hooking MGCopyAnswer (C Function) ---
// transform MGCopyAnswer to something we control.
// CFStringRef MGCopyAnswer(CFStringRef prop);

static CFStringRef (*original_MGCopyAnswer)(CFStringRef prop);

CFStringRef my_MGCopyAnswer(CFStringRef prop) {
    NSString *key = (__bridge NSString *)prop;
    // NSLog(@"[DeviceRotator] MGCopyAnswer called for: %@", key);
    
    if ([key isEqualToString:@"UniqueDeviceID"] || [key isEqualToString:@"UDID"]) {
        // Return a fake UDID (standard format: 40 hex chars)
        // For simplicity, we just hash the IDFV or generate one
        NSString *fakeUDID = [[GetStoredID(kCustomIDFVKey) stringByReplacingOccurrencesOfString:@"-" withString:@""] lowercaseString];
        fakeUDID = [fakeUDID stringByAppendingString:@"00000000"]; // Padding
        if (fakeUDID.length > 40) fakeUDID = [fakeUDID substringToIndex:40];
        
        return (__bridge_retained CFStringRef)fakeUDID;
    }
    
    // Serial Number
    if ([key isEqualToString:@"SerialNumber"]) {
        return (__bridge_retained CFStringRef)@"C02XYZ123ABC";
    }

    return original_MGCopyAnswer(prop);
}


// --- Setup ---

__attribute__((constructor))
static void initialize() {
    NSLog(@"[DeviceRotator] Loaded!");

    // 1. Swizzle IDFV
    Method originalIDFV = class_getInstanceMethod([UIDevice class], @selector(identifierForVendor));
    Method swizzledIDFV = class_getInstanceMethod([UIDevice class], @selector(swizzled_identifierForVendor));
    method_exchangeImplementations(originalIDFV, swizzledIDFV);
    
    // 2. Swizzle IDFA
    // Note: ASIdentifierManager might not be loaded, should load framework if needed or check class
    Class asClass = objc_getClass("ASIdentifierManager");
    if (asClass) {
        Method originalIDFA = class_getInstanceMethod(asClass, @selector(advertisingIdentifier));
        Method swizzledIDFA = class_getInstanceMethod(asClass, @selector(swizzled_advertisingIdentifier));
        method_exchangeImplementations(originalIDFA, swizzledIDFA);
    } else {
        NSLog(@"[DeviceRotator] ASIdentifierManager class not found, skipping IDFA hook.");
    }
    
    // 3. Hook MGCopyAnswer with fishhook
    struct rebinding rebindings[] = {
        {"MGCopyAnswer", (void *)my_MGCopyAnswer, (void **)&original_MGCopyAnswer}
    };
    rebind_symbols(rebindings, 1);
    
    // Add a way to trigger rotation (e.g., tap gesture or just on load)
    // For now, we rotate if specific file/flag exists or just provide a button hook if UI access is available.
    // Simplifying: Just printing that it's active. Rotation logic exists in `RotateIDs()` 
    // functionality is available if we want to expose it to UI.
}
