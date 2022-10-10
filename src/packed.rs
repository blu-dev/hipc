// Naming conventions taken from the Atmosphére Custom Firmware: https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/include/stratosphere/sf/sf_types.hpp

use core::ops::*;

#[const_trait]
trait ConstUnsigned:
    ~const BitAnd<Self, Output = Self> +
    ~const BitOr<Self, Output = Self> +
    ~const BitXor<Self, Output = Self> +
    ~const BitAndAssign<Self> +
    ~const BitOrAssign<Self> +
    ~const BitXorAssign<Self> + 
    ~const Shl<usize, Output = Self> +
    ~const Shr<usize, Output = Self> +
    ~const ShlAssign<usize> +
    ~const ShrAssign<usize> +
    ~const Not<Output = Self> + 
    ~const Default +
    ~const From<u8>
{}

impl const ConstUnsigned for u8 {}
impl const ConstUnsigned for u16 {}
impl const ConstUnsigned for u32 {}
impl const ConstUnsigned for u64 {}
impl const ConstUnsigned for usize {}


const fn bitmask<T: ~const ConstUnsigned>(lsb: usize, msb: usize) -> T {
    let mut mask: T = T::default();
    let mut current = lsb;
    while current < msb {
        mask |= T::from(1u8) << current;
        current += 1;
    }
    mask
}

const fn extract<T: ~const ConstUnsigned>(value: T, lsb: usize, msb: usize) -> T {
    (value & bitmask(lsb, msb)) >> lsb
}

const fn set<T: ~const ConstUnsigned>(src: T, dst: T, src_lsb: usize, dst_lsb: usize, len: usize) -> T {
    let value = extract(src, src_lsb, src_lsb + len);
    let new_value = dst & !bitmask::<T>(dst_lsb, dst_lsb + len);
    new_value | (value << dst_lsb)
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub struct StaticDescriptor([u32; 2]);

impl StaticDescriptor {
    pub const fn index(self) -> usize {
        extract(self.0[0] as usize, 0, 6)
    }

    pub const fn size(self) -> usize {
        extract(self.0[0] as usize, 16, 32)
    }

    pub const fn address(self) -> u64 {
        let addr = set(self.0[1] as u64, 0, 0, 0, 32);
        let addr = set(self.0[0] as u64, addr, 12, 32, 4);
        set(self.0[0] as u64, addr, 6, 36, 6)
    }

    pub const fn new(index: usize, size: usize, address: u64) -> Self {
        let first = set(index as u32, 0, 0, 0, 6);
        let first = set(address, first as u64, 36, 6, 6) as u32;
        let first = set(address, first as u64, 32, 12, 4) as u32;
        let first = set(size as u32, first, 0, 16, 16);
        let second = set(address, 0, 0, 0, 32) as u32;
        Self([first, second])
    }
}

impl const From<StaticDescriptor> for [u8; 8] {
    fn from(value: StaticDescriptor) -> Self {
        let mut out = [0u8; 8];

        let first = value.0[0].to_le_bytes();
        let second = value.0[1].to_le_bytes();

        let mut index = 0;
        while index < 4 {
            out[index] = first[index];
            out[index + 4] = second[index];
            index += 1;
        }

        out
    }
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub struct BufferDescriptor([u32; 3]);

impl BufferDescriptor {
    pub const fn size(self) -> usize {
        let size = 0u64;
        let size = set(self.0[0] as u64, size, 0, 0, 32);
        let size = set(self.0[2] as u64, size, 24, 32, 4);
        size as usize
    }

    pub const fn address(self) -> u64 {
        let address = 0u64;
        let address = set(self.0[1] as u64, address, 0, 0, 32);
        let address = set(self.0[2] as u64, address, 28, 32, 4);
        set(self.0[2] as u64, address, 2, 36, 22)
    }

    pub const fn mode(self) -> u8 {
        extract(self.0[2], 0, 2) as u8
    }

    pub const fn new(address: u64, size: usize, mode: u8) -> Self {
        let size_low = extract(size, 0, 32) as u32;
        let address_low = extract(address, 0, 32) as u32;
        let inner = 0u32;
        let inner = set(mode as u32, inner, 0, 0, 2);
        let inner = set(address, inner as u64, 32, 28, 4) as u32;
        let inner = set(size as u64, inner as u64, 32, 24, 4) as u32;
        let inner = set(address, inner as u64, 36, 2, 22) as u32;

        Self([size_low, address_low, inner])
    }
}

impl const From<BufferDescriptor> for [u8; 12] {
    fn from(value: BufferDescriptor) -> Self {
        let mut out = [0u8; 12];

        let first = value.0[0].to_le_bytes();
        let second = value.0[1].to_le_bytes();
        let third = value.0[2].to_le_bytes();

        let mut index = 0;
        while index < 4 {
            out[index] = first[index];
            out[index + 4] = second[index];
            out[index + 8] = third[index];
            index += 1;
        }

        out
    }
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub struct ReceiveListEntry([u32; 2]);

impl ReceiveListEntry {
    pub const fn size(self) -> usize {
        extract(self.0[1], 16, 32) as usize
    }

    pub const fn address(self) -> u64 {
        let address = set(self.0[0] as u64, 0, 0, 0, 32);
        set(self.0[1] as u64, address, 0, 32, 16)
    }

    pub const fn new(address: u64, size: usize) -> Self {
        let first = extract(address, 0, 32) as u32;
        let second = set(address, 0, 32, 0, 16) as u32;
        let second = set(size as u32, second, 0, 16, 16);

        Self([first, second])
    }
}

impl const From<ReceiveListEntry> for [u8; 8] {
    fn from(value: ReceiveListEntry) -> Self {
        let mut out = [0u8; 8];

        let first = value.0[0].to_le_bytes();
        let second = value.0[1].to_le_bytes();

        let mut index = 0;
        while index < 4 {
            out[index] = first[index];
            out[index + 4] = second[index];
            index += 1;
        }

        out
    }
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub struct SpecialHeader(u32);

impl SpecialHeader {
    pub const fn send_pid(self) -> bool {
        extract(self.0, 0, 1) != 0
    }

    pub const fn num_copy_handles(self) -> usize {
        extract(self.0, 1, 5) as usize
    }

    pub const fn num_move_handles(self) -> usize {
        extract(self.0, 5, 9) as usize
    }

    pub const fn new(send_pid: bool, num_copy_handles: usize, num_move_handles: usize) -> Self {
        let inner = set(send_pid as u32, 0, 0, 0, 1);
        let inner = set(num_copy_handles as u32, inner, 0, 1, 4);
        let inner = set(num_move_handles as u32, inner, 0, 5, 4);

        Self(inner)
    }
}

impl const From<SpecialHeader> for [u8; 4] {
    fn from(value: SpecialHeader) -> Self {
        value.0.to_le_bytes()
    }
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub struct Header([u32; 2]);

impl Header {
    pub const fn ty(self) -> u16 {
        extract(self.0[0], 0, 16) as u16
    }

    pub const fn num_send_statics(self) -> usize {
        extract(self.0[0], 16, 20) as usize
    }

    pub const fn num_send_buffers(self) -> usize {
        extract(self.0[0], 20, 24) as usize
    }

    pub const fn num_receive_buffers(self) -> usize {
        extract(self.0[0], 24, 28) as usize
    }

    pub const fn num_exchange_buffers(self) -> usize {
        extract(self.0[0], 28, 32) as usize
    }

    pub const fn raw_data_len(self) -> usize {
        extract(self.0[1], 0, 10) as usize
    }

    pub const fn receive_static_mode(self) -> u8 {
        extract(self.0[1], 10, 14) as u8
    }

    pub const fn receive_list_offset(self) -> usize {
        extract(self.0[1], 20, 31) as usize
    }

    pub const fn has_special_header(self) -> bool {
        extract(self.0[1], 31, 32) != 0
    }

    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        ty: u16,
        num_statics: usize,
        num_send_bufs: usize,
        num_recv_bufs: usize,
        num_exch_bufs: usize,
        raw_data_len: usize,
        recv_static_mode: u8,
        recv_list_offset: usize,
        has_special_header: bool
    ) -> Self
    {
        let first = set(ty as u32, 0, 0, 0, 16);
        let first = set(num_statics as u32, first, 0, 16, 4);
        let first = set(num_send_bufs as u32, first, 0, 20, 4);
        let first = set(num_recv_bufs as u32, first, 0, 24, 4);
        let first = set(num_exch_bufs as u32, first, 0, 28, 4);
        let second = set(raw_data_len as u32, 0, 0, 0, 10);
        let second = set(recv_static_mode as u32, second, 0, 10, 4);
        let second = set(recv_list_offset as u32, second, 0, 20, 11);
        let second = set(has_special_header as u32, second, 0, 31, 1);

        Self([first, second])
    }
}

impl const From<Header> for [u8; 8] {
    fn from(value: Header) -> Self {
        let mut out = [0u8; 8];

        let first = value.0[0].to_le_bytes();
        let second = value.0[1].to_le_bytes();

        let mut index = 0;
        while index < 4 {
            out[index] = first[index];
            out[index + 4] = second[index];
            index += 1;
        }

        out
    }
}