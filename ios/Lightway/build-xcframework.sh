#!/bin/bash -e

# Build Platform specific Frameworks
# iOS Device
xcodebuild archive \
    -scheme Lightway \
    -archivePath "./Build/ios.xcarchive" \
    -sdk iphoneos \
    SKIP_INSTALL=NO CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO \
    SUPPORTS_MACCATALYST=NO

# iOS Sim
xcodebuild archive \
    -scheme Lightway \
    -archivePath "./Build/ios_sim.xcarchive" \
    -sdk iphonesimulator \
    SKIP_INSTALL=NO CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO \
    SUPPORTS_MACCATALYST=NO

# Mac Catalyst
xcodebuild archive \
    -scheme Lightway \
    -archivePath "./Build/maccatalyst.xcarchive" \
    -destination 'platform=macOS,variant=Mac Catalyst' \
    SKIP_INSTALL=NO CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO

# Package XC Framework
xcodebuild -create-xcframework \
    -framework "./Build/ios.xcarchive/Products/Library/Frameworks/Lightway.framework" \
    -framework "./Build/ios_sim.xcarchive/Products/Library/Frameworks/Lightway.framework" \
    -framework "./Build/maccatalyst.xcarchive/Products/Library/Frameworks/Lightway.framework" \
    -output "./Build/Lightway.xcframework"
