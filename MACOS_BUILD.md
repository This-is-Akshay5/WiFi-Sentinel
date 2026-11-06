# WiFiSentinel macOS app bundle (Apple Silicon)

This build creates a real `WiFiSentinel.app` bundle with its own bundle identifier and the macOS Location Services usage description. It keeps writable databases, reports, captures, logs, and `.env` configuration under `~/Library/Application Support/WiFiSentinel`; GUI and dataset assets remain bundled read-only resources.

## Build

1. Run `./run_simulator.command` once to create/update `.venv-macos-arm64` and install the app dependencies. Quit WiFiSentinel.
2. Run `./build_macos_app.command`. The build script installs PyInstaller into that environment and creates `dist/WiFiSentinel.app`.
3. Move `dist/WiFiSentinel.app` to `/Applications` (or open it directly from `dist` for the first test). Launch it from Finder, not from Terminal.
4. When macOS asks for Location Services authorization, allow it. Then reopen WiFiSentinel and run Wi-Fi discovery again.
5. Verify the running app identity from a terminal with: `defaults read "/Applications/WiFiSentinel.app/Contents/Info" CFBundleIdentifier` and `defaults read "/Applications/WiFiSentinel.app/Contents/Info" NSLocationUsageDescription`. Expected bundle ID: `com.wifisentinel.desktop`.

## Data and configuration

The packaged app stores its local database, reports, captures, logs, and optional `.env` at `~/Library/Application Support/WiFiSentinel`. If you need OpenAI settings, place your `.env` there. Do not put API keys into the app bundle or commit them. The source-run development mode continues to use the project directory.

## Notes

- This is an Apple Silicon build (`arm64`) and must be built on the target Mac.
- The app requests Location Services authorization for access to nearby Wi-Fi identifiers. It does not request or store geographic coordinates.
- Permission approval is not a guarantee that every macOS/CoreWLAN version will expose every scan field. Verify that SSID/BSSID values are actually returned; WiFiSentinel must continue to show unavailable values honestly.
- The existing `run_simulator.command` remains the development launcher. Use the built `.app` for the permission test.
