#!/bin/sh
#python3 /usr/local/bin/pyinstaller time-decode-mac.spec --noconfirm
#mkdir -p dist/dmg
#rm -r dist/dmg/*
#cp -r "dist/Time Decode v$1.app" dist/dmg/
#test -f "dist/Time Decode v$1.dmg" && rm "dist/Time Decode v$1.dmg"
create-dmg \
  --volname "Time Decode v$1" \
  --volicon "icon.icns" \
  --window-pos 200 120 \
  --window-size 600 300 \
  --icon-size 100 \
  --icon "Time Decode v$1.app" 175 120 \
  --hide-extension "Time Decode v$1.app" \
  --app-drop-link 425 120 \
  --no-internet-enable \
  "dist/Time Decode v$1.dmg" \
  "dist/dmg/"
