#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <objc/runtime.h>
#include "fishhook.h"
#include <sys/stat.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>


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


// --- Jailbreak Detection Bypass ---

// List of common jailbreak-related paths
static NSArray *JailbreakPaths() {
    static NSArray *paths = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        paths = @[
            @"/Applications/Cydia.app",
            @"/Library/MobileSubstrate/MobileSubstrate.dylib",
            @"/bin/bash",
            @"/usr/sbin/sshd",
            @"/etc/apt",
            @"/private/var/lib/apt/",
            @"/private/var/lib/cydia",
            @"/private/var/stash",
            @"/private/var/tmp/cydia.log",
            @"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            @"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            @"/usr/libexec/cydia/",
            @"/usr/bin/sshd",
            @"/usr/libexec/sftp-server",
            @"/var/cache/apt",
            @"/var/lib/cydia",
            @"/var/log/syslog",
            @"/bin/sh",
            @"/etc/ssh/sshd_config",
            @"/Library/MobileSubstrate/DynamicLibraries",
            @"/var/mobile/Library/SBSettings/Themes",
            @"/usr/lib/libsubstrate.dylib",
            @"/usr/libexec/substrated",
            @"/.installed_unc0ver",
            @"/.bootstrapped_electra",
            @"/usr/lib/libjailbreak.dylib",
            @"/jb/lzma",
            @"/jb/offsets.plist",
            @"/usr/share/jailbreak/injectme.plist",
            @"/etc/apt/sources.list.d/electra.list",
            @"/etc/apt/sources.list.d/sileo.sources",
            @"/.bootstrapped",
            @"/usr/lib/TweakInject",
            @"/electra",
            @"/var/binpack",
            @"/Library/dpkg/info"
        ];
    });
    return paths;
}

static BOOL IsJailbreakPath(const char *path) {
    if (!path) return NO;
    NSString *pathStr = [NSString stringWithUTF8String:path];
    for (NSString *jbPath in JailbreakPaths()) {
        if ([pathStr hasPrefix:jbPath] || [pathStr isEqualToString:jbPath]) {
            return YES;
        }
    }
    return NO;
}

// Hook stat
static int (*original_stat)(const char *, struct stat *);
int my_stat(const char *path, struct stat *buf) {
    if (IsJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return original_stat(path, buf);
}

// Hook lstat
static int (*original_lstat)(const char *, struct stat *);
int my_lstat(const char *path, struct stat *buf) {
    if (IsJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return original_lstat(path, buf);
}

// Hook fopen
static FILE *(*original_fopen)(const char *, const char *);
FILE *my_fopen(const char *path, const char *mode) {
    if (IsJailbreakPath(path)) {
        errno = ENOENT;
        return NULL;
    }
    return original_fopen(path, mode);
}

// Hook access
static int (*original_access)(const char *, int);
int my_access(const char *path, int mode) {
    if (IsJailbreakPath(path)) {
        errno = ENOENT;
        return -1;
    }
    return original_access(path, mode);
}

// Hook fork (prevent fork-based jailbreak detection)
static pid_t (*original_fork)(void);
pid_t my_fork(void) {
    // Return -1 to simulate fork failure
    errno = ENOSYS;
    return -1;
}

// Hook system
static int (*original_system)(const char *);
int my_system(const char *cmd) {
    // Block system calls
    return -1;
}

// Hook _dyld_get_image_name
static const char *(*original_dyld_get_image_name)(uint32_t);
const char *my_dyld_get_image_name(uint32_t image_index) {
    const char *name = original_dyld_get_image_name(image_index);
    if (name) {
        // Check if it's a jailbreak-related dylib
        if (strstr(name, "MobileSubstrate") || 
            strstr(name, "substrate") || 
            strstr(name, "TweakInject") ||
            strstr(name, "Cephei") ||
            strstr(name, "Rocket") ||
            strstr(name, "PreferenceLoader")) {
            return "/System/Library/Frameworks/UIKit.framework/UIKit"; // Return safe path
        }
    }
    return name;
}

// Hook NSFileManager fileExistsAtPath
@interface NSFileManager (JBBypass)
- (BOOL)jb_fileExistsAtPath:(NSString *)path;
- (BOOL)jb_fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory;
@end

@implementation NSFileManager (JBBypass)
- (BOOL)jb_fileExistsAtPath:(NSString *)path {
    for (NSString *jbPath in JailbreakPaths()) {
        if ([path hasPrefix:jbPath] || [path isEqualToString:jbPath]) {
            return NO;
        }
    }
    return [self jb_fileExistsAtPath:path];
}

- (BOOL)jb_fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    for (NSString *jbPath in JailbreakPaths()) {
        if ([path hasPrefix:jbPath] || [path isEqualToString:jbPath]) {
            return NO;
        }
    }
    return [self jb_fileExistsAtPath:path isDirectory:isDirectory];
}
@end

// Hook canOpenURL (detects URL schemes like cydia://)
@interface UIApplication (JBBypass)
- (BOOL)jb_canOpenURL:(NSURL *)url;
@end

@implementation UIApplication (JBBypass)
- (BOOL)jb_canOpenURL:(NSURL *)url {
    NSString *scheme = [url.scheme lowercaseString];
    NSArray *jbSchemes = @[@"cydia", @"sileo", @"zbra", @"filza", @"activator"];
    if ([jbSchemes containsObject:scheme]) {
        return NO;
    }
    return [self jb_canOpenURL:url];
}
@end



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
        {"MGCopyAnswer", (void *)my_MGCopyAnswer, (void **)&original_MGCopyAnswer},
        {"stat", (void *)my_stat, (void **)&original_stat},
        {"lstat", (void *)my_lstat, (void **)&original_lstat},
        {"fopen", (void *)my_fopen, (void **)&original_fopen},
        {"access", (void *)my_access, (void **)&original_access},
        {"fork", (void *)my_fork, (void **)&original_fork},
        {"system", (void *)my_system, (void **)&original_system},
        {"_dyld_get_image_name", (void *)my_dyld_get_image_name, (void **)&original_dyld_get_image_name}
    };
    rebind_symbols(rebindings, 9);
    
    // 4. Swizzle NSFileManager
    Method originalFileExists1 = class_getInstanceMethod([NSFileManager class], @selector(fileExistsAtPath:));
    Method swizzledFileExists1 = class_getInstanceMethod([NSFileManager class], @selector(jb_fileExistsAtPath:));
    method_exchangeImplementations(originalFileExists1, swizzledFileExists1);
    
    Method originalFileExists2 = class_getInstanceMethod([NSFileManager class], @selector(fileExistsAtPath:isDirectory:));
    Method swizzledFileExists2 = class_getInstanceMethod([NSFileManager class], @selector(jb_fileExistsAtPath:isDirectory:));
    method_exchangeImplementations(originalFileExists2, swizzledFileExists2);
    
    // 5. Swizzle UIApplication canOpenURL
    Method originalCanOpen = class_getInstanceMethod([UIApplication class], @selector(canOpenURL:));
    Method swizzledCanOpen = class_getInstanceMethod([UIApplication class], @selector(jb_canOpenURL:));
    method_exchangeImplementations(originalCanOpen, swizzledCanOpen);
    
    NSLog(@"[DeviceRotator] Jailbreak bypass enabled!");
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
