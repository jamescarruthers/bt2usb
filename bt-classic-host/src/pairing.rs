//! Classic Bluetooth pairing: Secure Simple Pairing (SSP) and legacy PIN.
//!
//! SSP flow:
//!   1. AuthenticationRequested → controller initiates pairing
//!   2. IoCapabilityRequest → we reply with our IO capabilities
//!   3. IoCapabilityResponse → we learn the remote's capabilities
//!   4. Either UserConfirmationRequest (Just Works — auto-accepted) or
//!      UserPasskeyNotification (Passkey Entry — the passkey is handed up for
//!      display, and the user types it on the remote keyboard)
//!   5. SimplePairingComplete → pairing done (success or failure)
//!   6. LinkKeyNotification → new link key generated, store it
//!   7. AuthenticationComplete → authentication finished
//!
//! For bonded devices with a stored link key:
//!   1. AuthenticationRequested → controller checks link key
//!   2. LinkKeyRequest → we reply with stored key
//!   3. AuthenticationComplete → success (no SSP needed)
//!
//! # Why DisplayOnly
//!
//! The Pico has no screen, but it does have a host: the firmware streams log
//! events to whatever tool is driving it, which is display enough to show a
//! six-digit passkey. Claiming `DisplayOnly` is what makes keyboards pairable.
//!
//! The association model comes from both devices' IO capabilities:
//!
//! | Remote            | Model with `DisplayOnly` here                 |
//! |-------------------|-----------------------------------------------|
//! | KeyboardOnly      | Passkey Entry — we display, the user types it  |
//! | NoInputNoOutput   | Just Works — auto-accepted                     |
//! | DisplayOnly/YesNo | Just Works — auto-accepted                     |
//!
//! A keyboard has `KeyboardOnly` capability, so with the old
//! `NoInputNoOutput` setting the only available model was Just Works, which
//! keyboards requiring MITM protection refuse. Trackpads and mice report
//! `NoInputNoOutput` and still pair exactly as before.

use bt_hci::param::{BdAddr, IoCapability};

/// Our IO capability for SSP pairing.
///
/// `DisplayOnly` enables Passkey Entry against keyboards while leaving
/// pointing devices on Just Works. See the module docs for the full mapping.
pub const OUR_IO_CAPABILITY: IoCapability = IoCapability::DisplayOnly;

/// OOB (Out of Band) data presence flag.
/// We don't support OOB pairing.
pub const OUR_OOB_DATA: u8 = 0x00; // Not present

/// Default PIN used to answer a legacy (pre-SSP) `PinCodeRequest`.
///
/// Legacy keyboards expect the user to type the host's PIN and press Enter,
/// so the value is reported through [`PairingEvent::LegacyPin`] rather than
/// being answered silently.
pub const DEFAULT_LEGACY_PIN: &str = "0000";

/// Something the user needs to know, or act on, during pairing.
///
/// Reported through the callback registered with
/// `ClassicRunner::set_pairing_callback`, since pairing happens inside a
/// blocking connect and there is no other moment to surface it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PairingEvent {
    /// Passkey Entry: show this to the user, who types it on the remote
    /// keyboard and presses Enter. Always six digits, zero-padded.
    PasskeyDisplay(u32),
    /// Legacy pairing: we answered with this PIN, which the user must type on
    /// the remote keyboard followed by Enter.
    LegacyPin(&'static str),
    /// Just Works: numeric comparison auto-accepted, nothing for the user to do.
    JustWorks,
    /// The remote asked *us* to enter a passkey it is displaying. We have no
    /// input device, so pairing was declined.
    PasskeyEntryUnsupported,
}

/// Callback invoked when pairing needs to tell the user something.
///
/// A plain function pointer rather than a closure: this crate is `no_std` and
/// allocation-free, and the firmware's logging sinks are global anyway.
pub type PairingCallback = fn(&BdAddr, PairingEvent);

/// Pairing state tracker for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PairingState {
    /// No pairing in progress.
    Idle,
    /// Waiting for IoCapabilityRequest from controller.
    WaitingIoCap,
    /// Sent IoCapabilityRequestReply, waiting for remote's response.
    IoCapsExchanged,
    /// Waiting for UserConfirmationRequest or UserPasskeyNotification.
    WaitingConfirmation,
    /// Passkey displayed to the user; waiting for them to type it on the
    /// remote keyboard. This is the one pairing step gated on a human, so it
    /// can take considerably longer than the rest put together.
    WaitingPasskeyEntry,
    /// Sent UserConfirmationRequestReply, waiting for SimplePairingComplete.
    WaitingComplete,
    /// Pairing complete, waiting for LinkKeyNotification.
    WaitingLinkKey,
    /// Pairing finished (success or failure).
    Done,
}

/// Tracks the pairing state for a single connection.
pub struct PairingContext {
    pub state: PairingState,
    /// Remote device's IO capability (learned from IoCapabilityResponse).
    pub remote_io_cap: Option<IoCapability>,
    /// The remote BD_ADDR being paired with.
    pub peer_addr: BdAddr,
    /// Whether pairing succeeded.
    pub success: bool,
    /// Newly generated link key (from LinkKeyNotification).
    pub new_link_key: Option<[u8; 16]>,
    /// Link key type from LinkKeyNotification.
    pub link_key_type: u8,
    /// Passkey the remote must type, from UserPasskeyNotification.
    pub passkey: Option<u32>,
}

impl PairingContext {
    pub fn new(peer_addr: BdAddr) -> Self {
        Self {
            state: PairingState::Idle,
            remote_io_cap: None,
            peer_addr,
            success: false,
            new_link_key: None,
            link_key_type: 0,
            passkey: None,
        }
    }

    /// Start a new pairing attempt.
    pub fn start(&mut self) {
        self.state = PairingState::WaitingIoCap;
        self.remote_io_cap = None;
        self.success = false;
        self.new_link_key = None;
        self.passkey = None;
    }

    /// Handle IoCapabilityResponse event (remote's capabilities).
    pub fn on_io_capability_response(&mut self, io_cap: IoCapability) {
        self.remote_io_cap = Some(io_cap);
        self.state = PairingState::WaitingConfirmation;
    }

    /// Handle UserPasskeyNotification event: the remote is waiting for the
    /// user to type this passkey on its own keyboard.
    pub fn on_user_passkey_notification(&mut self, passkey: u32) {
        self.passkey = Some(passkey);
        self.state = PairingState::WaitingPasskeyEntry;
    }

    /// Handle SimplePairingComplete event.
    pub fn on_simple_pairing_complete(&mut self, success: bool) {
        self.success = success;
        self.state = if success {
            PairingState::WaitingLinkKey
        } else {
            PairingState::Done
        };
    }

    /// Handle LinkKeyNotification event.
    pub fn on_link_key_notification(&mut self, key: [u8; 16], key_type: u8) {
        self.new_link_key = Some(key);
        self.link_key_type = key_type;
        self.state = PairingState::Done;
    }
}
