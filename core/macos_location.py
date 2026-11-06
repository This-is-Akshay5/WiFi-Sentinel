"""Request macOS Location Services authorization for nearby Wi-Fi identifiers.

The app does not request or store geographic coordinates. CoreWLAN scan
identifiers are privacy-gated on supported macOS versions.
"""
from __future__ import annotations

_manager = None
_delegate = None


def request_location_authorization() -> int | None:
    """Request permission once the app bundle supplies NSLocationUsageDescription."""
    global _manager, _delegate
    try:
        import CoreLocation
        from AppKit import NSApplication
        from Foundation import NSObject
    except Exception as exc:
        print(f"[WiFiSentinel] CoreLocation bridge unavailable: {exc}", flush=True)
        return None

    # Ensure this process has an AppKit application context before requesting.
    NSApplication.sharedApplication()

    class LocationDelegate(NSObject):
        def locationManagerDidChangeAuthorization_(self, manager):
            try:
                status = int(manager.authorizationStatus())
            except Exception:
                status = None
            print(f"[WiFiSentinel] Location authorization status: {status}", flush=True)

    _manager = CoreLocation.CLLocationManager.alloc().init()
    _delegate = LocationDelegate.alloc().init()
    _manager.setDelegate_(_delegate)
    status = int(_manager.authorizationStatus())
    print(f"[WiFiSentinel] Current Location Services authorization: {status}", flush=True)
    if status == 0:  # kCLAuthorizationStatusNotDetermined
        _manager.requestWhenInUseAuthorization()
        print("[WiFiSentinel] Requested Location Services authorization for Wi-Fi scan identifiers.", flush=True)
    return status
