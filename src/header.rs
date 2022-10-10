
/// Maximum amount of PIDS which can be stored in the special header
/// 
/// Note: Preferably we would use a boolean here for `USE_PID` or something
///       along those lines, however that would require some
///       `where` clauses to properly evaluate, so just using a maximum
///       value and following the same format as other values is ideal.
const MAX_PIDS: usize = 0x01;

/// Maximum amount of copy handles which can be provided through the special header
const MAX_COPY: usize = 0x0F;

/// Maximum amount of move handles which can be provided through the special header
const MAX_MOVE: usize = 0x0F;

use crate::command::helpers;

/// Helper macro for creating a [`SpecialHeaderBuilder`] type
/// 
/// # Arguments
/// * `has_pid` - Boolean value for if the header has a PID or not
/// * `cp` - Number of copy handles
/// * `mv` - Number of move handles
#[macro_export]
macro_rules! header_ty {
    (true, $cp:expr, $mv:expr) => {
        $crate::header::SpecialHeaderBuilder<1, $cp, $mv, { $crate::header::consumed_space(1, $cp, $mv) }>
    };

    (false, $cp:expr, $mv:expr) => {
        $crate::header::SpecialHeaderBuilder<0, $cp, $mv, { $crate::header::consumed_space(0, $cp, $mv) }>
    };
}

pub use header_ty;

/// Builder for the optional special header in HIPC commands
/// 
/// # Generics
/// * `PIDS` - The number of program IDs to be sent with the special header (max of one)
/// * `CP` - The number of copy handles to be sent with the special header (max of 15)
/// * `MV` - The number of move handles to be sent with the special header (max of 15)
/// * `TOTAL` - The total number of bytes the special header consumes when serialized
/// 
/// All of the generic parameters are handled automatically by the builder functions and
/// to construct a new, empty builder, you should use [`new_builder`].
/// 
/// # Example
/// The following code could be used to build a special header for a HIPC command that includes
/// the handle to the current process (the kernel will resolve this handle upon copy).
/// ```
/// const PSEUDO_HANDLE_CURRENT_PROCESS: u32 = 0xFFFF_8001;
/// 
/// use hipc::header;
/// 
/// pub const fn current_proc_header() -> header::header_ty!(false, 1, 0) {
///     header::new_builder()
///         .with_copy_handle(PSEUDO_HANDLE_CURRENT_PROCESS)
/// }
/// ```
/// 
/// # Memory Layout
/// Once serialized to bytes, the special header contains the following layout:
/// 
/// | 32-bit Word | Purpose |
/// | ----------- | ------- |
/// | `0` | [Header](`crate::packed::SpecialHeader`) |
/// | ... | Process ID, 2 words and only present if specified |
/// | ... | Copy handles, 1 word each |
/// | ... | Move handles, 1 word each |
/// 
#[derive(Copy, Clone)]
pub struct SpecialHeaderBuilder<const PIDS: usize, const CP: usize, const MV: usize, const TOTAL: usize> {
    process_ids: [u64; PIDS],
    copy_handles: [u32; CP],
    move_handles: [u32; MV]
}

#[doc(hidden)]
pub const fn consumed_space(pids: usize, copy: usize, move_: usize) -> usize {
    pids * core::mem::size_of::<u64>() + copy * core::mem::size_of::<u32>() + move_ * core::mem::size_of::<u32>() + core::mem::size_of::<crate::packed::SpecialHeader>()
}

impl<const PIDS: usize, const CP: usize, const MV: usize, const TOTAL: usize> SpecialHeaderBuilder<PIDS, CP, MV, TOTAL> {
    /// Constructs a new, empty special header.
    /// 
    /// Due to this method requiring generics to be provided to the type to call,
    /// it is recommended to instead call [`new_builder`].
    pub const fn new() -> SpecialHeaderBuilder<0, 0, 0, 4> {
        SpecialHeaderBuilder {
            process_ids: [],
            copy_handles: [],
            move_handles: []
        }
    }

    /// Configures the special header to include the provided process ID
    /// 
    /// # Arguments
    /// * `process_id` - The process ID to include in the header
    /// 
    /// # Failures
    /// * The special header is already configured to use a special header
    pub const fn with_program_id(self, process_id: u64) -> SpecialHeaderBuilder<{ helpers::safe_increment(PIDS, MAX_PIDS, "Too many process ids!") }, CP, MV, { consumed_space(helpers::safe_increment(PIDS, MAX_PIDS, "Too many process ids!"), CP, MV) }> {
        SpecialHeaderBuilder {
            process_ids: helpers::push_array(self.process_ids, process_id),
            copy_handles: self.copy_handles,
            move_handles: self.move_handles
        }
    }

    /// Configures the special header so that the kernel will copy the provided handle
    /// 
    /// # Arguments
    /// * `handle` - The handle for the kernel to copy
    /// 
    /// # Failures
    /// * The special header has reached the maximum amount of handles allowed to be copied (15)
    pub const fn with_copy_handle(self, handle: u32) -> SpecialHeaderBuilder<PIDS, { helpers::safe_increment(CP, MAX_COPY, "Too many copy handles!") }, MV, { consumed_space(PIDS, helpers::safe_increment(CP, MAX_COPY, "Too many copy handles!"), MV) }> {
        SpecialHeaderBuilder {
            process_ids: self.process_ids,
            copy_handles: helpers::push_array(self.copy_handles, handle),
            move_handles: self.move_handles
        }
    }

    /// Configures the special header so that the kernel will move the provided handle
    /// 
    /// # Arguments
    /// * `handle` - The handle for the kernel to move
    /// 
    /// # Failures
    /// * The special header has reached the maximum amount of handles allowed to be moved (15)
    pub const fn with_move_handle(self, handle: u32) -> SpecialHeaderBuilder<PIDS, CP, { helpers::safe_increment(MV, MAX_MOVE, "Too many move handles!") }, { consumed_space(PIDS, CP, helpers::safe_increment(MV, MAX_MOVE, "Too many move handles!"))}> {
        SpecialHeaderBuilder {
            process_ids: self.process_ids,
            copy_handles: self.copy_handles,
            move_handles: helpers::push_array(self.move_handles, handle),
        }
    }

    /// Compiles the special header into the smallest byte array that can contain it
    /// 
    /// While you can call this, it's not very useful as the only place this is used
    /// is in a [command](crate::command::HipcCommandBuilder).
    pub const fn build(self) -> [u8; TOTAL] {
        // Get our empty byte array
        let mut out = [0u8; TOTAL];

        // Start our writer at index 0
        let mut write_index = 0;

        // Generate/write our actual u32 header
        let header = crate::packed::SpecialHeader::new(PIDS != 0, CP, MV);
        let raw_bytes: [u8; 4] = header.into();

        out = helpers::byte_array_write(out, raw_bytes, write_index);
        write_index += raw_bytes.len();

        // Write each PID we have (max of 1)
        let mut current = 0;
        while current < PIDS {
            let raw_bytes = self.process_ids[current].to_le_bytes();
            out = helpers::byte_array_write(out, raw_bytes, write_index);
            write_index += raw_bytes.len();
            current += 1;
        }

        // Write each of the copy handles (max of 15)
        current = 0;
        while current < CP {
            let raw_bytes = self.copy_handles[current].to_le_bytes();
            out = helpers::byte_array_write(out, raw_bytes, write_index);
            write_index += raw_bytes.len();
            current += 1;
        }

        // Write each of the move handles (max of 15)
        current = 0;
        while current < MV {
            let raw_bytes = self.move_handles[current].to_le_bytes();
            out = helpers::byte_array_write(out, raw_bytes, write_index);

            write_index += raw_bytes.len();
            current += 1;
        }

        // Return our serialized data
        out
    }
}

/// Constructs a new [`SpecialHeaderBuilder`]
/// 
/// # Example
/// The following example will create a new special header and include in it
/// the current program ID as well as the the handle to the current process.
/// ```
/// const PSEUDO_HANDLE_CURRENT_PROCESS: u32 = 0xFFFF_8001;
/// 
/// use hipc::header;
/// 
/// pub const fn current_program_header() -> header::header_ty!(true, 1, 0) {
///     header::new_builder()
///         .with_program_id(nx::get_current_program_id())
///         .with_copy_handle(PSEUDO_HANDLE_CURRENT_PROCESS)
/// }
/// 
/// # mod nx {
/// #     pub const fn get_current_program_id() -> u64 { 0 }
/// # }
/// ```
pub const fn new_builder() -> SpecialHeaderBuilder<0, 0, 0, 4> {
    SpecialHeaderBuilder::<0, 0, 0, 4>::new()
}