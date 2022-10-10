//! A library for working with the Nintendo Switch's HIPC (Horizon Inter-process Communication) protocol
#![allow(incomplete_features)]
#![no_std]
#![feature(const_trait_impl)]
#![feature(const_mut_refs)]
#![feature(generic_const_exprs)]
#![feature(const_convert)]

pub mod command;
pub mod header;
pub mod packed;

/// Command type for HIPC commands
#[repr(u16)]
pub enum CommandType {
    /// An invalid command type, also used by servers when issuing a response to the
    /// client
    Invalid = 0x0,

    /// An older form of a request command
    LegacyRequest = 0x1,

    /// Closes the session
    Close = 0x2,

    /// An older form of a control command
    LegacyControl = 0x3,

    /// A command to the server to perform some operation, or to receive
    /// some data.
    Request = 0x4,

    /// A command to the server to manage the connection, usually
    Control = 0x5,

    /// The same kind of command as [CommandType::Request], except with a
    /// token included
    RequestWithContext = 0x6,

    /// The same kind of command as [CommandType::Control], except with a
    /// token included
    ControlWithContext = 0x7
}

/// Helper trait for converting into an array of 32-bit words
#[const_trait]
pub trait IntoWords<const N: usize>: ~const Into<[u32; N]> {}

impl<const N: usize> const IntoWords<N> for [u32; N] {}

/// Helper trait for converting into an array of bytes
#[const_trait]
pub trait IntoBytes<const N: usize>: ~const Into<[u8; N]> {}

impl<const N: usize> const IntoBytes<N> for [u8; N] {}