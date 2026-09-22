//! HIDP (HID Profile) protocol implementation.
//!
//! HIDP runs over two L2CAP channels:
//! - Control (PSM 0x0011): Commands, GET/SET_REPORT, handshakes
//! - Interrupt (PSM 0x0013): Unsolicited input reports (HID data)
//!
//! Message format: header byte (upper nibble = type, lower = param) + payload.
//!
//! For a Classic keyboard:
//! - `SET_PROTOCOL(Boot)` on the Control channel pins reports to the 8-byte
//!   boot layout, matching the USB boot keyboard descriptor byte for byte
//! - Input reports then arrive on the Interrupt channel as DATA messages
//!
//! For the Magic Trackpad 2 over Classic Bluetooth:
//! - Input reports arrive on the Interrupt channel as DATA messages (0xA1)
//! - Touch data uses Report ID 0x31 with 4-byte header + N*9-byte touch points
//! - Multitouch enable: SET_REPORT(Feature, 0xF1, {0x02, 0x01}) on Control channel

pub mod client;
pub mod types;

pub use client::{HidClient, HidReport, MAX_REPORT_SIZE, PROTOCOL_BOOT, PROTOCOL_REPORT};
pub use types::{HandshakeResult, MessageType, ReportType, PSM_HID_CONTROL, PSM_HID_INTERRUPT};
