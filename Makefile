TARGET = DeviceRotator.dylib
SYSROOT = /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk
ARCHS = -arch arm64 -arch arm64e
LIBS = -framework Foundation -framework UIKit -framework AdSupport
CC = clang

all: $(TARGET)

$(TARGET): DeviceRotator.mm fishhook.c
	$(CC) $(ARCHS) -isysroot $(SYSROOT) -dynamiclib -o $@ $^ $(LIBS) -fobjc-arc

clean:
	rm -f $(TARGET)
