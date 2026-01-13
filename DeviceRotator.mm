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
}


// --- UI Implementation (Floating Button) ---

@interface UIButton (Draggable)
@end

@implementation UIButton (Draggable)
- (void)touchesMoved:(NSSet *)touches withEvent:(UIEvent *)event {
    UITouch *touch = [touches anyObject];
    CGPoint nowPoint = [touch locationInView:self.superview];
    CGPoint prevPoint = [touch previousLocationInView:self.superview];
    float deltaX = nowPoint.x - prevPoint.x;
    float deltaY = nowPoint.y - prevPoint.y;
    self.center = CGPointMake(self.center.x + deltaX, self.center.y + deltaY);
}
@end

static void ShowAlert(NSString *title, NSString *message) {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    UIViewController *rootVC = keyWindow.rootViewController;
    // Walk up to find the top VC
    while (rootVC.presentedViewController) {
        rootVC = rootVC.presentedViewController;
    }
    [rootVC presentViewController:alert animated:YES completion:nil];
}

static void SetupFloatingButton() {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIWindow *window = [UIApplication sharedApplication].keyWindow;
        if (!window) return;
        
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        [btn setTitle:@"Reset ID" forState:UIControlStateNormal];
        [btn setBackgroundColor:[UIColor redColor]];
        [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        btn.frame = CGRectMake(50, 100, 100, 40);
        btn.layer.cornerRadius = 20;
        btn.layer.zPosition = 9999; // Always on top
        
        [btn addTarget:window action:@selector(handleResetTap) forControlEvents:UIControlEventTouchUpInside];
        
        // Add gesture for simple dragging (implemented in category for simplicity or just naive implementation)
        // For a raw dylib, keeping it simple:
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:window action:@selector(handleDrag:)];
        [btn addGestureRecognizer:pan];
        
        [window addSubview:btn];
    });
}

// Helper methods on UIWindow (using category to add methods)
@interface UIWindow (ButtonLogic)
@end

@implementation UIWindow (ButtonLogic)
- (void)handleResetTap {
    RotateIDs();
    ShowAlert(@"Success", @"Device IDs have been rotated.\nPlease restart the app for changes to fully apply.");
}

- (void)handleDrag:(UIPanGestureRecognizer *)gesture {
    UIView *btn = gesture.view;
    CGPoint translation = [gesture translationInView:self];
    btn.center = CGPointMake(btn.center.x + translation.x, btn.center.y + translation.y);
    [gesture setTranslation:CGPointMake(0,0) inView:self];
}
@end


// Hook makeKeyAndVisible to inject button
@interface UIWindow (Hook)
- (void)swizzled_makeKeyAndVisible;
@end

@implementation UIWindow (Hook)
- (void)swizzled_makeKeyAndVisible {
    [self swizzled_makeKeyAndVisible];
    SetupFloatingButton();
}
@end

__attribute__((constructor))
static void initialize_ui() {
    // Swizzle UIWindow makeKeyAndVisible
    Method original = class_getInstanceMethod([UIWindow class], @selector(makeKeyAndVisible));
    Method swizzled = class_getInstanceMethod([UIWindow class], @selector(swizzled_makeKeyAndVisible));
    method_exchangeImplementations(original, swizzled);
}
