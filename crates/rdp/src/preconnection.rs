//! The RDP Preconnection PDU (MS-RDPEPS, Session Selection Extension): sent
//! right after the TCP connection, before the X.224 Connection Request, so a
//! listener can hand the connection to the right RDP source. Remote
//! Assistance and Desktop Sharing listeners take version 1 with the
//! invitation's `SID` as Id and refuse version 2 (MS-RDPEPS 6 <1>, <9>).

use crate::cursor::Put;

const RDP_PRECONNECTION_PDU_V1: u32 = 0x0000_0001;
/// RDP_PRECONNECTION_PDU_V1 is always 16 bytes (3.1.5.1).
const V1_LEN: u32 = 16;

/// RDP_PRECONNECTION_PDU_V1 (2.2.1.1): cbSize, Flags (zero), Version, Id.
pub fn pdu_v1(id: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(V1_LEN as usize);
    out.put_u32(V1_LEN);
    out.put_u32(0);
    out.put_u32(RDP_PRECONNECTION_PDU_V1);
    out.put_u32(id);
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn v1_matches_the_spec_example() {
        // MS-RDPEPS 4: Id 0xEEC699EB.
        assert_eq!(
            super::pdu_v1(0xEEC6_99EB),
            [
                0x10, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0xeb, 0x99, 0xc6, 0xee
            ]
        );
    }
}
