use bt2usb_core::classic::{
    cod_is_keyboard, cod_is_peripheral, cod_is_pointing, cod_major_device_class,
    translate_keyboard_report,
};

// ============ Class of Device tests ============
//
// CoD arrives from HCI little-endian, so a CoD of 0x002540 (keyboard) is the
// byte sequence [0x40, 0x25, 0x00].

/// Apple Magic Trackpad 2: Peripheral / pointing device.
const COD_TRACKPAD: [u8; 3] = [0x80, 0x25, 0x00];
/// A typical Bluetooth keyboard: Peripheral / keyboard.
const COD_KEYBOARD: [u8; 3] = [0x40, 0x25, 0x00];
/// Keyboard with integrated pointing device.
const COD_COMBO: [u8; 3] = [0xC0, 0x25, 0x00];
/// Peripheral major class, uncategorized minor class (e.g. some gamepads).
const COD_PERIPHERAL_OTHER: [u8; 3] = [0x08, 0x25, 0x00];
/// Audio/Video major class (0x04) — a pair of headphones.
const COD_HEADPHONES: [u8; 3] = [0x04, 0x24, 0x04];

#[test]
fn major_device_class_extracted_from_middle_byte() {
    assert_eq!(cod_major_device_class(&COD_KEYBOARD), Some(0x05));
    assert_eq!(cod_major_device_class(&COD_HEADPHONES), Some(0x04));
}

#[test]
fn short_cod_is_rejected() {
    assert_eq!(cod_major_device_class(&[0x40, 0x25]), None);
    assert!(!cod_is_peripheral(&[0x40, 0x25]));
    assert!(!cod_is_keyboard(&[]));
}

#[test]
fn peripherals_recognised() {
    assert!(cod_is_peripheral(&COD_KEYBOARD));
    assert!(cod_is_peripheral(&COD_TRACKPAD));
    assert!(cod_is_peripheral(&COD_COMBO));
    assert!(cod_is_peripheral(&COD_PERIPHERAL_OTHER));
    assert!(!cod_is_peripheral(&COD_HEADPHONES));
}

#[test]
fn keyboards_recognised() {
    assert!(cod_is_keyboard(&COD_KEYBOARD));
    assert!(cod_is_keyboard(&COD_COMBO));
    assert!(!cod_is_keyboard(&COD_TRACKPAD));
    assert!(!cod_is_keyboard(&COD_PERIPHERAL_OTHER));
}

#[test]
fn keyboard_minor_class_needs_peripheral_major_class() {
    // Same minor-class bits, but an Audio/Video major class. A pair of
    // headphones must never be treated as a keyboard.
    let cod = [0x40, 0x24, 0x04];
    assert!(!cod_is_keyboard(&cod));
}

#[test]
fn pointing_devices_recognised() {
    assert!(cod_is_pointing(&COD_TRACKPAD));
    assert!(cod_is_pointing(&COD_COMBO));
    assert!(!cod_is_pointing(&COD_KEYBOARD));
}

// ============ Keyboard report translation tests ============

#[test]
fn boot_report_passes_through() {
    // Left Shift held, 'a' and 'b' pressed.
    let report = [0x02, 0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(translate_keyboard_report(&report), Some(report));
}

#[test]
fn boot_report_reserved_byte_is_cleared() {
    let report = [0x00, 0x7F, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
    let expected = [0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(translate_keyboard_report(&report), Some(expected));
}

#[test]
fn report_protocol_id_is_stripped() {
    let report = [0x01, 0x02, 0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00];
    let expected = [0x02, 0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(translate_keyboard_report(&report), Some(expected));
}

#[test]
fn key_release_is_forwarded() {
    let report = [0u8; 8];
    assert_eq!(translate_keyboard_report(&report), Some(report));
}

#[test]
fn six_key_rollover_is_preserved() {
    let report = [0x00, 0x00, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
    assert_eq!(translate_keyboard_report(&report), Some(report));
}

#[test]
fn other_lengths_are_rejected() {
    // Nothing here is a keyboard report, and guessing would type characters
    // the user never pressed.
    assert_eq!(translate_keyboard_report(&[]), None);
    assert_eq!(translate_keyboard_report(&[0x00, 0x01, 0x02]), None);
    assert_eq!(translate_keyboard_report(&[0u8; 7]), None);
    assert_eq!(translate_keyboard_report(&[0u8; 10]), None);
}

#[test]
fn nine_byte_report_with_foreign_id_is_rejected() {
    // Report ID 0x02 is typically a consumer-control (media key) report with
    // an entirely different layout.
    let report = [0x02, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(translate_keyboard_report(&report), None);
}

#[test]
fn magic_trackpad_touch_report_is_rejected() {
    // Report ID 0x31 with a 4-byte header — must not be mistaken for keys.
    let report = [0x31, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    assert_eq!(translate_keyboard_report(&report), None);
}
