// Phase 1 skeleton — compiles to WASM and exposes a single `score_transaction`
// function via wasm-bindgen. Full decode + scoring logic is implemented in Phase 5.

use wasm_bindgen::prelude::*;

mod signatures;

/// Scored result returned to the TypeScript bridge.
/// Phase 5 replaces this with a full discriminated union (ThreatScoreResult).
#[wasm_bindgen]
pub struct ScoreResult {
    pub score: u8,
    pub ok: bool,
}

/// Entry point called by the TypeScript WASM bridge.
///
/// `raw_tx_hex` — hex-encoded raw EVM transaction bytes (with or without 0x prefix).
///
/// Returns a score in [0, 100]. Returns ok=false on any decode error (fail-open
/// per ADR 001 — consuming middleware must treat ok=false as score=0).
#[wasm_bindgen]
pub fn score_transaction(raw_tx_hex: &str) -> ScoreResult {
    let hex_str = raw_tx_hex.trim_start_matches("0x");

    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(_) => {
            return ScoreResult { score: 0, ok: false };
        }
    };

    let score = compute_score(&bytes);
    ScoreResult { score, ok: true }
}

/// Derives a threat score from decoded transaction bytes.
/// Phase 5 replaces this stub with full RLP decode + ABI parameter analysis.
fn compute_score(calldata: &[u8]) -> u8 {
    if calldata.len() < 4 {
        // Too short to contain a method selector — benign or contract creation
        return 0;
    }

    let selector: [u8; 4] = calldata[..4].try_into().expect("len >= 4 checked above");

    if signatures::is_high_risk(&selector) {
        // High-risk selector detected — assign a high base score.
        // Phase 5 will layer additional heuristics on top.
        return 85;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_calldata_scores_zero() {
        let result = score_transaction("0x");
        assert!(result.ok);
        assert_eq!(result.score, 0);
    }

    #[test]
    fn invalid_hex_returns_error() {
        let result = score_transaction("0xnothex");
        assert!(!result.ok);
    }

    #[test]
    fn approve_selector_scores_high() {
        // approve(address,uint256) = 0x095ea7b3 followed by dummy params
        let result = score_transaction("0x095ea7b3000000000000000000000000deadbeef");
        assert!(result.ok);
        assert!(result.score >= 80, "approve selector must score >= 80, got {}", result.score);
    }

    #[test]
    fn transfer_from_selector_scores_high() {
        // transferFrom(address,address,uint256) = 0x23b872dd
        let result = score_transaction("0x23b872dd000000000000000000000000deadbeef");
        assert!(result.ok);
        assert!(result.score >= 80, "transferFrom selector must score >= 80, got {}", result.score);
    }

    #[test]
    fn eth_block_number_data_scores_zero() {
        // No recognized high-risk selector
        let result = score_transaction("0xaabbccdd");
        assert!(result.ok);
        assert_eq!(result.score, 0);
    }
}
