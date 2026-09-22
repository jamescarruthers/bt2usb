//! Bluetooth Classic helpers: Class of Device decoding and HID keyboard
//! report translation.
//!
//! These are pure functions so they can be unit tested on the host, away
//! from the firmware's async/HCI machinery.

/// Major Device Class for "Peripheral" — keyboards, mice, trackpads, gamepads.
pub const MAJOR_CLASS_PERIPHERAL: u8 = 0x05;

/// Extract the Major Device Class (bits 12:8) from a 3-byte Class of Device.
///
/// CoD arrives from HCI little-endian:
///   cod[0] = bits 7:0   (format type + minor device class)
///   cod[1] = bits 15:8  (major device class + low major service bits)
///   cod[2] = bits 23:16 (major service class)
pub fn cod_major_device_class(cod: &[u8]) -> Option<u8> {
    if cod.len() < 3 {
        return None;
    }
    Some(cod[1] & 0x1F)
}

/// Whether a Class of Device identifies a Peripheral (HID) device.
pub fn cod_is_peripheral(cod: &[u8]) -> bool {
    cod_major_device_class(cod) == Some(MAJOR_CLASS_PERIPHERAL)
}

/// Whether a Class of Device identifies a keyboard.
///
/// For the Peripheral major class the top two bits of the Minor Device Class
/// (bits 7:6 of the CoD, i.e. the top of `cod[0]`) select the device kind:
///   00 = uncategorized, 01 = keyboard, 10 = pointing device,
///   11 = combo keyboard/pointing device.
///
/// Combos count as keyboards: their keystrokes are what we can forward.
pub fn cod_is_keyboard(cod: &[u8]) -> bool {
    if !cod_is_peripheral(cod) {
        return false;
    }
    matches!((cod[0] >> 6) & 0x03, 0b01 | 0b11)
}

/// Whether a Class of Device identifies a pointing device (mouse, trackpad).
pub fn cod_is_pointing(cod: &[u8]) -> bool {
    if !cod_is_peripheral(cod) {
        return false;
    }
    matches!((cod[0] >> 6) & 0x03, 0b10 | 0b11)
}

/// Length of a USB/Bluetooth boot-protocol keyboard report.
pub const BOOT_KEYBOARD_REPORT_LEN: usize = 8;

/// Report ID used by the keyboard input report of virtually every Classic
/// keyboard that runs in report protocol rather than boot protocol.
pub const KEYBOARD_REPORT_ID: u8 = 0x01;

/// Translate a HIDP input report from a Classic keyboard into the 8-byte boot
/// keyboard report the USB side sends: `[modifiers, 0, key1..key6]`.
///
/// Two shapes are accepted, covering what keyboards emit in practice:
///
/// - 8 bytes — boot protocol, already `[modifiers, reserved, key1..key6]`.
///   This is what a keyboard sends once `SET_PROTOCOL(Boot)` is accepted.
/// - 9 bytes starting with report ID `0x01` — report protocol with the same
///   payload behind a report ID, for keyboards that refuse boot protocol.
///
/// Anything else returns `None` rather than guessing: a misread report types
/// characters the user never pressed, while a dropped one is merely silent.
///
/// The reserved byte is forced to zero — some keyboards put OEM data there,
/// and hosts expect it clear.
pub fn translate_keyboard_report(data: &[u8]) -> Option<[u8; BOOT_KEYBOARD_REPORT_LEN]> {
    let body = match data.len() {
        BOOT_KEYBOARD_REPORT_LEN => data,
        len if len == BOOT_KEYBOARD_REPORT_LEN + 1 && data[0] == KEYBOARD_REPORT_ID => &data[1..],
        _ => return None,
    };

    let mut out = [0u8; BOOT_KEYBOARD_REPORT_LEN];
    out[0] = body[0];
    out[1] = 0;
    out[2..].copy_from_slice(&body[2..BOOT_KEYBOARD_REPORT_LEN]);
    Some(out)
}
