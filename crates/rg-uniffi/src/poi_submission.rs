use rg_core::PoiProof;

/// A POI proof between proving and submitting.
#[derive(uniffi::Object)]
pub struct PoiSubmission {
    pub(crate) proof: PoiProof,
}
