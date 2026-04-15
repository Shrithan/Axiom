//! macOS APIs only. No scraping, AppleScript, Accessibility or recording permissions.
#[cfg(target_os = "macos")]
mod mac {
    use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString, NSWorkspace};
    use objc2_foundation::NSString;
    pub fn version() -> i64 {
        objc2::rc::autoreleasepool(|_| NSPasteboard::generalPasteboard().changeCount() as i64)
    }
    pub fn read() -> Result<Option<(i64, String)>, String> {
        objc2::rc::autoreleasepool(|_| {
            let board = NSPasteboard::generalPasteboard();
            let before = board.changeCount() as i64;
            let value = board.stringForType(unsafe { NSPasteboardTypeString });
            let Some(value) = value else {
                return Ok(None);
            };
            if value.length() > 2_000_000 {
                return Err("Clipboard text exceeds limits".into());
            }
            let text = value.to_string();
            if text.len() > 2_000_000 {
                return Err("Clipboard text exceeds limits".into());
            }
            if board.changeCount() as i64 != before {
                return Ok(None);
            }
            Ok(Some((before, text)))
        })
    }
    pub fn replace(expected: i64, text: Option<&str>) -> Result<Option<i64>, String> {
        objc2::rc::autoreleasepool(|_| {
            let board = NSPasteboard::generalPasteboard();
            if board.changeCount() as i64 != expected {
                return Ok(None);
            }
            board.clearContents();
            if let Some(text) = text {
                if !board
                    .setString_forType(&NSString::from_str(text), unsafe { NSPasteboardTypeString })
                {
                    return Err("Clipboard write failed".into());
                }
            }
            Ok(Some(board.changeCount() as i64))
        })
    }
    pub fn application() -> (String, String) {
        objc2::rc::autoreleasepool(|_| {
            NSWorkspace::sharedWorkspace()
                .frontmostApplication()
                .map(|app| {
                    (
                        app.localizedName()
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                        app.bundleIdentifier()
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                    )
                })
                .unwrap_or_default()
        })
    }
}
#[cfg(target_os = "macos")]
pub use mac::*;
#[cfg(not(target_os = "macos"))]
pub fn version() -> i64 {
    0
}
#[cfg(not(target_os = "macos"))]
pub fn read() -> Result<Option<(i64, String)>, String> {
    Err("Clipboard source is implemented on macOS only".into())
}
#[cfg(not(target_os = "macos"))]
pub fn replace(_: i64, _: Option<&str>) -> Result<Option<i64>, String> {
    Err("Clipboard enforcement is implemented on macOS only".into())
}
#[cfg(not(target_os = "macos"))]
pub fn application() -> (String, String) {
    Default::default()
}
