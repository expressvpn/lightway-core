#!/bin/bash -e

# Build Platform specific Frameworks
# iOS Device
xcodebuild archive \
    -scheme Lightway \
    -archivePath "./Build/ios.xcarchive" \
    -sdk iphoneos \
    SKIP_INSTALL=NO CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO PLATFORM=universal

# iOS Sim
xcodebuild archive \
    -scheme Lightway \
    -archivePath "./Build/ios_sim.xcarchive" \
    -sdk iphonesimulator \
    SKIP_INSTALL=NO CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO PLATFORM=universal

# Package XC Framework
xcodebuild -create-xcframework \
    -framework "./Build/ios.xcarchive/Products/Library/Frameworks/Lightway.framework" \
    -framework "./Build/ios_sim.xcarchive/Products/Library/Frameworks/Lightway.framework" \
    -output "./Build/Lightway.xcframework"
