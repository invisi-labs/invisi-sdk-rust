//! 域分离常量 — 与 protocol-docs/01-protocol/1.2-commitment.md:12-21 对齐.
//! 数值固定, 不可改 (改了链上验证会失败).
//!
//! SPEC-009a 使用的: D_NKEY / D_IDENT / D_PAY / D_NULL / D_DERIVE
//! 预留 (SPEC-009d credit 体系等后续 SPEC 使用): D_CREDIT / D_CNULL / D_NKHASH / D_REFLINK

pub const D_NKEY:    u64 = 1;
pub const D_IDENT:   u64 = 2;
pub const D_PAY:     u64 = 3;
pub const D_NULL:    u64 = 4;
// 预留 (本 SPEC 不实现):
// pub const D_CREDIT:  u64 = 5;
// pub const D_CNULL:   u64 = 6;
// pub const D_NKHASH:  u64 = 7;
pub const D_DERIVE:  u64 = 8;
// pub const D_REFLINK: u64 = 9;
