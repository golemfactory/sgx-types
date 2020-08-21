#[cfg(feature = "with-serde")]
use serde::{Serialize, Deserialize};

/// Raw bytes of IAS report and signature
#[derive(Clone, Debug)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct AttestationResponse {
    pub report: Vec<u8>,
    pub signature: Vec<u8>,
}
