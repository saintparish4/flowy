/// High-risk EVM method selectors (first 4 bytes of keccak256 of the ABI signature).
///
/// These are defined here — never inline in lib.rs — so the list can be
/// reviewed, extended, and tested in isolation from the scoring logic.
///
/// Sources: Ethereum ABI spec + observed wallet-drainer attack patterns.

/// Returns true if the given 4-byte selector matches a known high-risk method.
pub fn is_high_risk(selector: &[u8; 4]) -> bool {
    HIGH_RISK_SELECTORS.contains(selector)
}

/// Canonical list of high-risk selectors.
///
/// Each entry is the keccak256(signature)[0..4] in big-endian byte order.
/// Phase 5 may extend this with a runtime-loaded custom list from config.
const HIGH_RISK_SELECTORS: &[[u8; 4]] = &[
    // approve(address,uint256)
    [0x09, 0x5e, 0xa7, 0xb3],
    // transferFrom(address,address,uint256)
    [0x23, 0xb8, 0x72, 0xdd],
    // multicall(bytes[])
    [0xac, 0x96, 0x50, 0xd8],
    // setApprovalForAll(address,bool)  — ERC-721 / ERC-1155 drainer vector
    [0xa2, 0x2c, 0xb4, 0x65],
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approve_is_high_risk() {
        assert!(is_high_risk(&[0x09, 0x5e, 0xa7, 0xb3]));
    }

    #[test]
    fn transfer_from_is_high_risk() {
        assert!(is_high_risk(&[0x23, 0xb8, 0x72, 0xdd]));
    }

    #[test]
    fn multicall_is_high_risk() {
        assert!(is_high_risk(&[0xac, 0x96, 0x50, 0xd8]));
    }

    #[test]
    fn set_approval_for_all_is_high_risk() {
        assert!(is_high_risk(&[0xa2, 0x2c, 0xb4, 0x65]));
    }

    #[test]
    fn benign_selector_is_not_high_risk() {
        // balanceOf(address) = 0x70a08231
        assert!(!is_high_risk(&[0x70, 0xa0, 0x82, 0x31]));
    }

    #[test]
    fn unknown_selector_is_not_high_risk() {
        assert!(!is_high_risk(&[0xde, 0xad, 0xbe, 0xef]));
    }
}
