#import <Foundation/Foundation.h>
#import <IOKit/ps/IOPowerSources.h>
#import <IOKit/ps/IOPSKeys.h>
int ottto_power_state(void) {
    @autoreleasepool {
        CFTypeRef info = IOPSCopyPowerSourcesInfo();
        if (info == NULL) return -1;
        CFStringRef source = IOPSGetProvidingPowerSourceType(info);
        int ac = source == NULL ? -1 : (CFEqual(source, CFSTR(kIOPMACPowerKey)) ? 1 : 0);
        CFRelease(info); // source is borrowed (Get); info is owned (Copy).
        NSProcessInfo *process = NSProcessInfo.processInfo;
        if (![process respondsToSelector:@selector(isLowPowerModeEnabled)]) return -1;
        if (ac < 0) return -1;
        return ac && !process.isLowPowerModeEnabled ? 1 : 0;
    }
}
