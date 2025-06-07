#!/bin/sh

# The bundle version fields expect a numeric version with three components, so
# we set it to "0.0.0" for Git snapshot builds.
if [ -n "$GIT_COMMIT_SHA" ]
then
	bundle_version=0.0.0
else
	bundle_version=$VERSION
fi

cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>REHex</string>
	
	<key>CFBundleDisplayName</key>
	<string>REHex</string>
	
	<key>CFBundleIdentifier</key>
	<string>net.solemnwarning.rehex</string>
	
	<key>CFBundleVersion</key>
	<string>${bundle_version}</string>
	
	<key>CFBundleShortVersionString</key>
	<string>${bundle_version}</string>
	
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	
	<key>CFBundleSignature</key>
	<string>????</string>
	
	<key>CFBundleExecutable</key>
	<string>REHex</string>
	
	<key>LSApplicationCategoryType</key>
	<string>public.app-category.utilities</string>
	
	<key>LSMinimumSystemVersion</key>
	<string>10.13</string>
	
	<key>NSPrincipalClass</key>
	<string>NSApplication</string>
	
	<key>CFBundleIconFile</key>
	<string>REHex.icns</string>
</dict>
</plist>
EOF
