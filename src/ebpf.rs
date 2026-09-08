use rbpf::EbpfVmRaw;

// eBPF instruction
pub const SEED_PROG: &[u8] = &[
    // mov32 r0, 0
    0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add32 r0, 1
    0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // exit
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// eBPF instructions are exactly 8 bytes
pub fn validate_bytes(input: &[u8]) -> bool {
    input.len() >= 8 && input.len() % 8 == 0
}

// Create an rbpf VM from an eBPF program.
pub fn create_vm(input: &[u8]) -> Result<EbpfVmRaw<'_>, ()> {
    EbpfVmRaw::new(Some(input)).map_err(|_| ())
}
