//! Fixed domain tags. Changing a value changes every associated commitment.

pub const D_NKEY: u64 = 1;
pub const D_IDENT: u64 = 2;
pub const D_PAY: u64 = 3;
pub const D_NULL: u64 = 4;
pub const D_DERIVE: u64 = 8;
/// Change-key domain shared with the Go and TypeScript implementations.
pub const D_CHANGE_NKEY: u64 = 11;
