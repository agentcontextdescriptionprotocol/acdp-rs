//! Typed ACDP 0.3.0 exceptions + the shared `AcdpError` → Python
//! mapping.
//!
//! Mirrors the `SsrfRejected` / `DidResolutionError` convention: each
//! exception is a stable, catchable class corresponding to one
//! RFC-ACDP-0007 §5 wire code, so host code can branch on the *kind*
//! of failure without parsing message strings. The Node binding
//! carries the same taxonomy as stable `.code` strings
//! (`invalid_log_proof`, `immutable_field`,
//! `invalid_lifecycle_transition`).

use acdp::error::AcdpError;
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyRuntimeError, PyValueError};
use pyo3::PyErr;

create_exception!(
    acdp,
    InvalidLogProof,
    PyException,
    "A transparency-log artifact failed verification (RFC-ACDP-0012 \
     §9, §11): an inclusion path that does not fold to the checkpoint \
     root, a failed consistency proof, a checkpoint whose signature \
     does not verify, or a malformed leaf/checkpoint/proof object. \
     Permanent — a bad proof will not verify on retry."
);

create_exception!(
    acdp,
    ImmutableField,
    PyException,
    "A lifecycle (or future mutation) request attempted to supply or \
     alter immutable body content (RFC-ACDP-0013 §6, §10). Bodies are \
     immutable; lifecycle endpoints mutate registry state only."
);

create_exception!(
    acdp,
    InvalidLifecycleTransition,
    PyException,
    "The requested lifecycle transition conflicts with the context's \
     current retraction state (RFC-ACDP-0013 §6 step 4, §10): retract \
     of an already-retracted context, or republish of a never-retracted \
     one. Retryable only after the state changes."
);

/// Map a core [`AcdpError`] to the binding's exception taxonomy:
/// the three 0.3.0 wire codes get their typed exceptions,
/// `schema_violation` stays a `ValueError` (malformed input), and
/// everything else is a `RuntimeError` carrying the core message —
/// the same fallbacks the pre-0.3.0 methods use.
pub(crate) fn map_acdp_error(e: AcdpError) -> PyErr {
    match &e {
        AcdpError::InvalidLogProof(_) => InvalidLogProof::new_err(e.to_string()),
        AcdpError::ImmutableField(_) => ImmutableField::new_err(e.to_string()),
        AcdpError::InvalidLifecycleTransition(_) => {
            InvalidLifecycleTransition::new_err(e.to_string())
        }
        AcdpError::SchemaViolation(_) => PyValueError::new_err(e.to_string()),
        _ => PyRuntimeError::new_err(e.to_string()),
    }
}
