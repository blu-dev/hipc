use crate::{packed::*, CommandType, IntoWords, IntoBytes, header::SpecialHeaderBuilder};


/// The maximum number of statics/in pointers the command can hold
const MAX_SEND_STATICS: usize = 0x0F;

/// The maximum number of send buffers the command can hold
const MAX_SEND_BUFFERS: usize = 0x0F;

/// The maximum number of receive buffers the command can hold
const MAX_RECV_BUFFERS: usize = 0x0F;

/// The maximum number of exchange buffers the command can hold
const MAX_EXCH_BUFFERS: usize = 0x0F;

/// The maximum number of receive statics/out pointers the command can hold
const MAX_RECV_STATICS: usize = 0x0D;

/// The maximum number of special headers the command can hold
const MAX_SPECIAL_HDRS: usize = 0x01;

/// The maximum number of pointer buffers the command can hold
/// 
/// Note: This is mutually exclusive from receive statics
const MAX_POINTER_BUFS: usize = 0x01;

/// The maximum size of the command (since it goes on the TLS)
const MAX_TLS_BUFFER_SIZE: usize = 0x100;

/// Command builder for a HIPC Command
/// 
/// # Generics
/// * `SS` - The number of InPointers (or "Send Statics") to pass in the command (max 15)
/// * `SB` - The number of InMapAlias (or "Send Buffers") to pass in the command (max 15)
/// * `RB` - The number of OutMapAlias (or "Write Buffers") to pass in the command (max 15)
/// * `EB` - The number of InOutMapAlias (or "Exchange Buffers") to pass in the command (max 15)
/// * `RS` - The number of OutPointers (or "Receive Statics") to pass in the command[^outptr] (max 13)
/// * `SH` - The number of special headers to pass in the command (max 1)
/// * `PB` - The number of pointer buffers to pass in the command[^outptr] (max 1)
/// * `SH_PIDS` - The number of process IDs the special header contains
/// * `SH_COPY` - The number of copy handles the special header contains
/// * `SH_MOVE` - The number of move handles the special header contains
/// * `SH_TOTAL` - The total number of bytes the special header will consume
/// * `LEN` - The length, in 32-bit words, of the raw data payload
/// * `INLINE_BUFFER_LEN` - The length, in bytes, of the inline buffer[^outptr]
/// * `TOTAL` - The total number of bytes this command will consume
/// * `Data` - The raw data payload
/// * `InlineBuffer` - The inline buffer[^outptr]
/// 
/// [^outptr]: Receive statics, pointer buffers, and the inline buffer are all mutually exclusive.
pub struct HipcCommandBuilder
<
    const SS: usize, // Number of send statics 
    const SB: usize, // Number of send buffers 
    const RB: usize, // Number of recv buffers 
    const EB: usize, // Number of exch buffers 
    const RS: usize, // Number of recv statics 
    const SH: usize, // Number of special headers
    const PB: usize, // Number of pointer buffers

    const SH_PIDS: usize,
    const SH_COPY: usize,
    const SH_MOVE: usize,
    const SH_TOTAL: usize,
    
    const LEN: usize, // The number of 32-bit words in the raw-data payload
    const INLINE_BUFFER_LEN: usize, // The number of bytes in the inlined receive buffer

    const TOTAL: usize, // The total amount of space remaining that can still be used, doubles as the number of space available for the inlined receive buffer
    Data: IntoWords<LEN>, // The actual raw data
    InlineBuffer: IntoBytes<INLINE_BUFFER_LEN>, // The inline buffer
>
{
    ty: CommandType,
    send_statics: [StaticDescriptor; SS],
    send_buffers: [BufferDescriptor; SB],
    recv_buffers: [BufferDescriptor; RB],
    exch_buffers: [BufferDescriptor; EB],
    recv_statics: [ReceiveListEntry; RS],
    special_hdrs: [SpecialHeaderBuilder<SH_PIDS, SH_COPY, SH_MOVE, SH_TOTAL>; SH],
    pointer_bufs: [ReceiveListEntry; PB],
    raw_data: Data,
    inline_buffer: InlineBuffer
}

#[doc(hidden)]
pub mod helpers {
    use super::*;

    /// Panics when multiple of the receive list arguments are set simultaneously
    /// 
    /// # Arguments
    /// * `recv_statics` - The number of receive list entries to use
    /// * `inline_buff_len` - The length of the inline buffer at the end of the command
    /// * `has_pointer_buffer` - There is one receive list entry and it's intended to collect all of the input statics.
    /// 
    /// # Panicking
    /// * Panics if multiple of the above parameters are set simultaneously
    #[track_caller]
    const fn panic_on_invalid_recv_list(recv_statics: usize, inline_buff_len: usize, has_pointer_buffer: bool) {
        if recv_statics != 0 && inline_buff_len != 0 {
            panic!("Static receivers found with an inline buffer, this combination is illegal");
        }
        if recv_statics != 0 && has_pointer_buffer {
            panic!("Static receivers found with a setting for a pointer buffer, this combination is illegal");
        }
        if inline_buff_len != 0 && has_pointer_buffer {
            panic!("Inline buffer found with a setting for a pointer buffer, this combination is illegal");
        }
    }

    /// Calculates the consumed space in the command, to ensure that the user does
    /// not exceed the command space limitations
    /// 
    /// # Arguments
    /// * `send_statics` - The number of statics
    /// * `send_buffers` - The number of read buffers
    /// * `recv_buffers` - The number of rw buffers
    /// * `exch_buffers` - The number of exchange buffers
    /// * `recv_statics` - The number of entries in the receive list
    /// * `raw_len` - The number of 32-bit words in the raw data payload
    /// * `inline_buff_len` - The number of bytes in the inlined receive list buffer
    /// * `has_special_header` - If the command has a special header
    /// * `has_pointer_buffer` - If the command has a pointer buffer for the receive list
    /// 
    /// # Panicking
    /// * Panics under the same circumstances as [`panic_on_invalid_recv_list`]
    #[allow(clippy::too_many_arguments)]
    #[track_caller]
    pub const fn consumed_space(
        send_statics: usize,
        send_buffers: usize,
        recv_buffers: usize,
        exch_buffers: usize,
        recv_statics: usize,
        raw_len: usize,
        inline_buff_len: usize,
        special_header_total: usize,
        has_pointer_buffer: bool
    ) -> usize
    {
        // Check out receive list rq
        panic_on_invalid_recv_list(recv_statics, inline_buff_len, has_pointer_buffer);

        let mut total = core::mem::size_of::<Header>();
        total += core::mem::size_of::<StaticDescriptor>() * send_statics;
        total += core::mem::size_of::<BufferDescriptor>() * send_buffers;
        total += core::mem::size_of::<BufferDescriptor>() * recv_buffers;
        total += core::mem::size_of::<BufferDescriptor>() * exch_buffers;
        total += core::mem::size_of::<u32>() * raw_len;
        total += special_header_total;

        if recv_statics > 0 {
            total += core::mem::size_of::<ReceiveListEntry>() * recv_statics;
        } else if inline_buff_len != 0 {
            total += inline_buff_len;
        } else if has_pointer_buffer {
            total += core::mem::size_of::<ReceiveListEntry>();
        }

        total
    }

    /// Calculates the consumed space in the command
    /// 
    /// Calls [`consumed_space`] internally and then checks it against the maximum buffer size allowed
    /// on the TLS.
    /// 
    /// # Panics
    /// * The same situations as [`consumed_space`]
    /// * The space consumed currently is greater than the space allowed
    #[allow(clippy::too_many_arguments)]
    #[track_caller]
    pub const fn consumed_space_for_tls(
        send_statics: usize,
        send_buffers: usize,
        recv_buffers: usize,
        exch_buffers: usize,
        recv_statics: usize,
        raw_len: usize,
        inline_buff_len: usize,
        special_header_total: usize,
        has_pointer_buffer: bool
    ) -> usize {
        let total = consumed_space(
            send_statics,
            send_buffers,
            recv_buffers,
            exch_buffers,
            recv_statics,
            raw_len,
            inline_buff_len,
            special_header_total,
            has_pointer_buffer
        );

        if total > MAX_TLS_BUFFER_SIZE {
            panic!("Size is greater than what the TLS supports!");
        }

        total
    }

    /// Increments a value at compile time, panicking if it exceeds the maximum allowed value
    /// 
    /// # Arguments
    /// * `current` - The current value
    /// * `max` - The maximum value
    /// * `err_msg` - The panic message if incrementing fails
    /// 
    /// # Panicking
    /// * `current` >= `max`
    #[track_caller]
    pub const fn safe_increment(current: usize, max: usize, err_msg: &'static str) -> usize {
        if current >= max {
            panic!("{}", err_msg);
        }

        current + 1
    }

    /// Pushes a value to an array at compile time, extending its length
    /// 
    /// # Arguments
    /// * `current` - The current array
    /// * `next` - The value to push
    /// 
    /// # Returns
    /// * The extended array
    pub const fn push_array<T: Copy + Clone, const N: usize, const N2: usize>(current: [T; N], next: T) -> [T; N2] {
        let mut new = [next; N2];
        let mut index = 0;
        while index < N {
            new[index] = current[index];
            index += 1;
        }
        new
    }

    /// Gets the receiving mode for the command based on the receive list arguments
    /// 
    /// # Arguments
    /// * `recv_statics` - The number of InPointers (or "Receive Statics") for the command
    /// * `inline_buff_len` - The number of bytes the inline buffer consumes
    /// * `has_pointer_buffer` - If the command contains a pointer buffer
    /// 
    /// All arguments are mutually exclusive
    /// 
    /// # Panicking
    /// * More than one argument is non-zero/non-false
    #[track_caller]
    pub const fn get_recv_mode(recv_statics: usize, inline_buff_len: usize, has_pointer_buffer: bool) -> u8 {
        panic_on_invalid_recv_list(recv_statics, inline_buff_len, has_pointer_buffer);

        if recv_statics != 0 {
            (recv_statics as u8) + 2
        } else if inline_buff_len != 0 {
            1
        } else if has_pointer_buffer {
            2
        } else {
            0
        }
    }

    /// Writes to a byte array at compile time.
    /// 
    /// # Arguments
    /// * `base` - The current array
    /// * `input` - The array to source data from
    /// * `start` - The start index of where to write to
    /// 
    /// # Panicking
    /// * `start + input.len() > base.len()`
    #[track_caller]
    pub const fn byte_array_write<const N: usize, const N2: usize>(mut base: [u8; N], input: [u8; N2], start: usize) -> [u8; N] {
        if start + N2 > N {
            panic!("Input data will exceed base!");
        }

        let mut index = 0;
        while index < N2 {
            base[start + index] = input[index];
            index += 1;
        }

        base
    }
}

macro_rules! make_ty {
    () => { 
        HipcCommandBuilder
        <
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            { helpers::consumed_space(0, 0, 0, 0, 0, 0, 0, 0, false) },
            [u32; 0],
            [u8; 0]
        >
    };

    (send_static => $x:expr) => {
        HipcCommandBuilder
        <
            { $x },
            SB,
            RB,
            EB,
            RS,
            SH,
            PB,
            SH_PIDS,
            SH_COPY,
            SH_MOVE,
            SH_TOTAL,
            LEN,
            INLINE_BUFFER_LEN,
            { helpers::consumed_space($x, SB, RB, EB, RS, LEN, INLINE_BUFFER_LEN, SH_TOTAL, PB != 0) },
            Data,
            InlineBuffer
        >
    };

    (send_buffer => $x:expr) => {
        HipcCommandBuilder
        <
            SS,
            { $x },
            RB,
            EB,
            RS,
            SH,
            PB,
            SH_PIDS,
            SH_COPY,
            SH_MOVE,
            SH_TOTAL,
            LEN,
            INLINE_BUFFER_LEN,
            { helpers::consumed_space(SS, $x, RB, EB, RS, LEN, INLINE_BUFFER_LEN, SH_TOTAL, PB != 0) },
            Data,
            InlineBuffer
        >
    };

    (recv_buffer => $x:expr) => {
        HipcCommandBuilder
        <
            SS,
            SB,
            { $x },
            EB,
            RS,
            SH,
            PB,
            SH_PIDS,
            SH_COPY,
            SH_MOVE,
            SH_TOTAL,
            LEN,
            INLINE_BUFFER_LEN,
            { helpers::consumed_space(SS, SB, $x, EB, RS, LEN, INLINE_BUFFER_LEN, SH_TOTAL, PB != 0) },
            Data,
            InlineBuffer
        >
    };

    (exch_buffer => $x:expr) => {
        HipcCommandBuilder
        <
            SS,
            SB,
            RB,
            { $x },
            RS,
            SH,
            PB,
            SH_PIDS,
            SH_COPY,
            SH_MOVE,
            SH_TOTAL,
            LEN,
            INLINE_BUFFER_LEN,
            { helpers::consumed_space(SS, SB, RB, $x, RS, LEN, INLINE_BUFFER_LEN, SH_TOTAL, PB != 0) },
            Data,
            InlineBuffer
        >
    };

    (recv_static => $x:expr) => {
        HipcCommandBuilder
        <
            SS,
            SB,
            RB,
            EB,
            { $x },
            SH,
            PB,
            SH_PIDS,
            SH_COPY,
            SH_MOVE,
            SH_TOTAL,
            LEN,
            INLINE_BUFFER_LEN,
            { helpers::consumed_space(SS, SB, RB, EB, $x, LEN, INLINE_BUFFER_LEN, SH_TOTAL, PB != 0) },
            Data,
            InlineBuffer
        >
    };

    (special_header => ($x:expr, $pids:expr, $cp:expr, $mv:expr, $total:expr)) => {
        HipcCommandBuilder
        <
            SS,
            SB,
            RB,
            EB,
            RS,
            { $x },
            PB,
            { $pids },
            { $cp },
            { $mv },
            { $total },
            LEN,
            INLINE_BUFFER_LEN,
            { helpers::consumed_space(SS, SB, RB, EB, RS, LEN, INLINE_BUFFER_LEN, $total, PB != 0) },
            Data,
            InlineBuffer
        >
    };

    (pointer_buffer => $x:expr) => {
        HipcCommandBuilder
        <
            SS,
            SB,
            RB,
            EB,
            RS,
            SH,
            { $x },
            SH_PIDS,
            SH_COPY,
            SH_MOVE,
            SH_TOTAL,
            LEN,
            INLINE_BUFFER_LEN,
            { helpers::consumed_space(SS, SB, RB, EB, RS, LEN, INLINE_BUFFER_LEN, SH_TOTAL, $x != 0) },
            Data,
            InlineBuffer
        >
    };

    (raw_data => ($T:ty, $new_len:expr)) => {
        HipcCommandBuilder
        <
            SS,
            SB,
            RB,
            EB,
            RS,
            SH,
            PB,
            SH_PIDS,
            SH_COPY,
            SH_MOVE,
            SH_TOTAL,
            { $new_len },
            INLINE_BUFFER_LEN,
            { helpers::consumed_space(SS, SB, RB, EB, RS, $new_len, INLINE_BUFFER_LEN, SH_TOTAL, PB != 0) },
            $T,
            InlineBuffer
        >
    };

    (inline_buffer => ($T:ty, $new_len:expr)) => {
        HipcCommandBuilder
        <
            SS,
            SB,
            RB,
            EB,
            RS,
            SH,
            PB,
            SH_PIDS,
            SH_COPY,
            SH_MOVE,
            SH_TOTAL,
            LEN,
            { $new_len },
            { helpers::consumed_space(SS, SB, RB, EB, RS, LEN, $new_len, SH_TOTAL, PB != 0) },
            Data,
            $T
        >
    };
}

impl
<
    const SS: usize,
    const SB: usize,
    const RB: usize,
    const EB: usize,
    const RS: usize,
    const SH: usize,
    const PB: usize,

    const SH_PIDS: usize,
    const SH_COPY: usize,
    const SH_MOVE: usize,
    const SH_TOTAL: usize,

    const LEN: usize,
    const INLINE_BUFFER_LEN: usize,

    const TOTAL: usize,
    Data: IntoWords<LEN> + Copy,
    InlineBuffer: IntoBytes<INLINE_BUFFER_LEN> + Copy
>
HipcCommandBuilder<SS, SB, RB, EB, RS, SH, PB, SH_PIDS, SH_COPY, SH_MOVE, SH_TOTAL, LEN, INLINE_BUFFER_LEN, TOTAL, Data, InlineBuffer>
{
    /// Constructs a new, empty command.
    /// 
    /// Because this function requires type parameters to be called properly, it is recommended
    /// to call [`new_builder`] instead.
    pub const fn new(ty: CommandType) -> make_ty!() {
        HipcCommandBuilder::<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, [u32; 0], [u8; 0]> {
            ty,
            send_statics: [],
            send_buffers: [],
            recv_buffers: [],
            exch_buffers: [],
            recv_statics: [],
            special_hdrs: [],
            pointer_bufs: [],
            raw_data: [],
            inline_buffer: []
        }
    }

    /// Adds an InPointer/"Send Static" to this command (max 15)
    pub const fn with_send_static(self, desc: StaticDescriptor) -> make_ty!(send_static => helpers::safe_increment(SS, MAX_SEND_STATICS, "Too many send statics!")) {
        HipcCommandBuilder {
            ty: self.ty,
            send_statics: helpers::push_array(self.send_statics, desc),
            send_buffers: self.send_buffers,
            recv_buffers: self.recv_buffers,
            exch_buffers: self.exch_buffers,
            recv_statics: self.recv_statics,
            special_hdrs: self.special_hdrs,
            pointer_bufs: self.pointer_bufs,
            raw_data: self.raw_data,
            inline_buffer: self.inline_buffer
        }
    }

    /// Adds an InMapAlias/"Send Buffer" to this command (max 15)
    pub const fn with_send_buffer(self, desc: BufferDescriptor) -> make_ty!(send_buffer => helpers::safe_increment(SB, MAX_SEND_BUFFERS, "Too many send buffers!")) {
        HipcCommandBuilder {
            ty: self.ty,
            send_statics: self.send_statics,
            send_buffers: helpers::push_array(self.send_buffers, desc),
            recv_buffers: self.recv_buffers,
            exch_buffers: self.exch_buffers,
            recv_statics: self.recv_statics,
            special_hdrs: self.special_hdrs,
            pointer_bufs: self.pointer_bufs,
            raw_data: self.raw_data,
            inline_buffer: self.inline_buffer
        }
    }

    /// Adds an OutMapAlias/"Receive Buffer" to this command (max 15)
    pub const fn with_recv_buffer(self, desc: BufferDescriptor) -> make_ty!(recv_buffer => helpers::safe_increment(RB, MAX_RECV_BUFFERS, "Too many recv buffers!")) {
        HipcCommandBuilder {
            ty: self.ty,
            send_statics: self.send_statics,
            send_buffers: self.send_buffers,
            recv_buffers: helpers::push_array(self.recv_buffers, desc),
            exch_buffers: self.exch_buffers,
            recv_statics: self.recv_statics,
            special_hdrs: self.special_hdrs,
            pointer_bufs: self.pointer_bufs,
            raw_data: self.raw_data,
            inline_buffer: self.inline_buffer
        }
    }

    /// Adds an InOutMapAlias/"Exchange Buffer" to this command (max 15)
    pub const fn with_exch_buffer(self, desc: BufferDescriptor) -> make_ty!(exch_buffer => helpers::safe_increment(EB, MAX_EXCH_BUFFERS, "Too many exch buffers!")) {
        HipcCommandBuilder {
            ty: self.ty,
            send_statics: self.send_statics,
            send_buffers: self.send_buffers,
            recv_buffers: self.recv_buffers,
            exch_buffers: helpers::push_array(self.exch_buffers, desc),
            recv_statics: self.recv_statics,
            special_hdrs: self.special_hdrs,
            pointer_bufs: self.pointer_bufs,
            raw_data: self.raw_data,
            inline_buffer: self.inline_buffer
        }
    }

    /// Adds an OutPointer/"Receive Static" to this command (max 13)
    pub const fn with_recv_static(self, desc: ReceiveListEntry) -> make_ty!(recv_static => helpers::safe_increment(RS, MAX_RECV_STATICS, "Too many recv statics!")) {
        HipcCommandBuilder {
            ty: self.ty,
            send_statics: self.send_statics,
            send_buffers: self.send_buffers,
            recv_buffers: self.recv_buffers,
            exch_buffers: self.exch_buffers,
            recv_statics: helpers::push_array(self.recv_statics, desc),
            special_hdrs: self.special_hdrs,
            pointer_bufs: self.pointer_bufs,
            raw_data: self.raw_data,
            inline_buffer: self.inline_buffer
        }
    }

    /// Adds a special header to this command (max 1)
    pub const fn with_special_header<
        const PIDS: usize,
        const CP: usize,
        const MV: usize,
        const TOTAL_: usize
    >(
        self,
        header: SpecialHeaderBuilder<PIDS, CP, MV, TOTAL_>
    ) -> make_ty!(special_header => (helpers::safe_increment(SH, MAX_SPECIAL_HDRS, "Too many special headers!"), PIDS, CP, MV, TOTAL_)) {
        HipcCommandBuilder {
            ty: self.ty,
            send_statics: self.send_statics,
            send_buffers: self.send_buffers,
            recv_buffers: self.recv_buffers,
            exch_buffers: self.exch_buffers,
            recv_statics: self.recv_statics,
            special_hdrs: helpers::push_array([], header),
            pointer_bufs: self.pointer_bufs,
            raw_data: self.raw_data,
            inline_buffer: self.inline_buffer
        }
    }

    /// Adds a pointer buffer to this command (max 1)
    pub const fn with_pointer_buffer(self, desc: ReceiveListEntry) -> make_ty!(pointer_buffer => helpers::safe_increment(PB, MAX_POINTER_BUFS, "Too many pointer buffers!")) {
        HipcCommandBuilder {
            ty: self.ty,
            send_statics: self.send_statics,
            send_buffers: self.send_buffers,
            recv_buffers: self.recv_buffers,
            exch_buffers: self.exch_buffers,
            recv_statics: self.recv_statics,
            special_hdrs: self.special_hdrs,
            pointer_bufs: helpers::push_array(self.pointer_bufs, desc),
            raw_data: self.raw_data,
            inline_buffer: self.inline_buffer
        }
    }

    /// Adds the raw data payload to this command
    pub const fn with_raw_data<const N: usize, T: IntoWords<N> + Copy>(self, data: T) -> make_ty!(raw_data => (T, N))
    {
        HipcCommandBuilder {
            ty: self.ty,
            send_statics: self.send_statics,
            send_buffers: self.send_buffers,
            recv_buffers: self.recv_buffers,
            exch_buffers: self.exch_buffers,
            recv_statics: self.recv_statics,
            special_hdrs: self.special_hdrs,
            pointer_bufs: self.pointer_bufs,
            raw_data: data,
            inline_buffer: self.inline_buffer
        }
    }

    /// Adds an inlined buffer to this command (max 1)
    pub const fn with_inline_buffer<const N: usize, T: IntoBytes<N> + Copy>(self, data: T) -> make_ty!(inline_buffer => (T, N))
    where
        [u8; N]: From<T>
    {
        HipcCommandBuilder {
            ty: self.ty,
            send_statics: self.send_statics,
            send_buffers: self.send_buffers,
            recv_buffers: self.recv_buffers,
            exch_buffers: self.exch_buffers,
            recv_statics: self.recv_statics,
            special_hdrs: self.special_hdrs,
            pointer_bufs: self.pointer_bufs,
            raw_data: self.raw_data,
            inline_buffer: data
        }
    }

    /// Builds the command into a sequence of bytes
    pub const fn build(self) -> [u8; TOTAL]
    where
        Data: ~const IntoWords<LEN>,
        InlineBuffer: ~const IntoBytes<INLINE_BUFFER_LEN>,
    {
        let mut raw = [0u8; TOTAL];

        let header = Header::new(
            self.ty as u16,
            SS,
            SB,
            RB,
            EB,
            LEN,
            helpers::get_recv_mode(RS, INLINE_BUFFER_LEN, PB != 0),
            0,
            SH != 0
        );

        let header_bytes: [u8; 8] = header.into();

        raw = helpers::byte_array_write(raw, header_bytes, 0);

        let mut write_index = header_bytes.len();

        let mut counter = 0;
        while counter < SH {
            let special_header_bytes = self.special_hdrs[counter].build();
            raw = helpers::byte_array_write(raw, special_header_bytes, write_index);

            write_index += special_header_bytes.len();
            counter += 1;
        }

        counter = 0;
        while counter < SS {
            let desc_bytes: [u8; 8] = self.send_statics[counter].into();
            raw = helpers::byte_array_write(raw, desc_bytes, write_index);

            write_index += desc_bytes.len();
            counter += 1;
        }

        counter = 0;
        while counter < SB {
            let desc_bytes: [u8; 12] = self.send_buffers[counter].into();
            raw = helpers::byte_array_write(raw, desc_bytes, write_index);

            write_index += desc_bytes.len();
            counter += 1;
        }

        counter = 0;
        while counter < RB {
            let desc_bytes: [u8; 12] = self.recv_buffers[counter].into();
            raw = helpers::byte_array_write(raw, desc_bytes, write_index);

            write_index += desc_bytes.len();
            counter += 1;
        }

        counter = 0;
        while counter < EB {
            let desc_bytes: [u8; 12] = self.exch_buffers[counter].into();
            raw = helpers::byte_array_write(raw, desc_bytes, write_index);

            write_index += desc_bytes.len();
            counter += 1;
        }

        let data: [u32; LEN] = self.raw_data.into();
        counter = 0;
        while counter < LEN {
            let raw_bytes = data[counter].to_le_bytes();
            raw = helpers::byte_array_write(raw, raw_bytes, write_index);

            write_index += raw_bytes.len();
            counter += 1;
        }

        if INLINE_BUFFER_LEN > 0 {
            let data: [u8; INLINE_BUFFER_LEN] = self.inline_buffer.into();
            write_index = (write_index + 15) & !16;
            helpers::byte_array_write(raw, data, write_index);
            write_index += data.len();
        }
        
        counter = 0;
        while counter < PB {
            let raw_bytes: [u8; 8] = self.pointer_bufs[counter].into();
            raw = helpers::byte_array_write(raw, raw_bytes, write_index);

            write_index += raw_bytes.len();
            counter += 1;
        }

        counter = 0;
        while counter < RS {
            let raw_bytes: [u8; 8] = self.recv_statics[counter].into();
            raw = helpers::byte_array_write(raw, raw_bytes, write_index);

            write_index += raw_bytes.len();
            counter += 1;
        }

        raw
    }
}

/// Creates a new, empty builder for the command given the type
pub const fn new_builder(ty: CommandType) -> make_ty!() {
    HipcCommandBuilder::<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, [u32; 0], [u8; 0]>::new(ty)
}