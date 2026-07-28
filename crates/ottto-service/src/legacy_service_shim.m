#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>

int ottto_legacy_smappservice_status(const char *plist_name) {
    if (plist_name == NULL) {
        return -1;
    }

    @autoreleasepool {
        if (@available(macOS 13.0, *)) {
            NSString *name = [NSString stringWithUTF8String:plist_name];
            if (name == nil) {
                return -1;
            }
            SMAppService *service = [SMAppService agentServiceWithPlistName:name];
            return (int)service.status;
        }
    }
    return -1;
}

int ottto_unregister_legacy_smappservice(const char *plist_name) {
    if (plist_name == NULL) {
        return 0;
    }

    @autoreleasepool {
        if (@available(macOS 13.0, *)) {
            NSString *name = [NSString stringWithUTF8String:plist_name];
            if (name == nil) {
                return 0;
            }
            SMAppService *service = [SMAppService agentServiceWithPlistName:name];
            NSError *error = nil;
            return [service unregisterAndReturnError:&error] ? 1 : 0;
        }
    }
    return 0;
}
