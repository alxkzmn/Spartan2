//! This library implements Spartan, a high-speed SNARK.
//! We currently implement a non-preprocessing version of Spartan
//! that is generic over the polynomial commitment and evaluation argument (i.e., a PCS).
#![deny(
  // warnings,
  // unused,
  future_incompatible,
  nonstandard_style,
  rust_2018_idioms,
  // missing_docs
)]
#![allow(non_snake_case)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::type_complexity)]
#![forbid(unsafe_code)]

// private modules
mod math;
pub mod r1cs;

#[macro_use]
mod macros;

// public modules
pub mod bellpepper;
pub mod digest;
pub mod errors;
pub mod neutronnova;
pub mod polys;
pub mod provider;
pub mod spartan;
pub mod sumcheck;
pub mod traits;
pub mod zk_spartan;
pub mod zk_sumcheck;

/// Start a span + timer, return `(Span, Instant)`.
macro_rules! start_span {
    ($name:expr $(, $($fmt:tt)+)?) => {{
        let span       = info_span!($name $(, $($fmt)+)?);
        let span_clone = span.clone();    // lives as long as the guard
        let _guard      = span_clone.enter();
        (span, Instant::now())
    }};
}
pub(crate) use start_span;

// Tracing creates static event metadata that refers back to the event itself.
// Aeneas rejects these mutually dependent declarations before generating Lean;
// the verifier's logging and clocks must therefore be removed at compile time.
// A macro also removes the log arguments, including calls to timer.elapsed().
// The ordinary build keeps the same spans, timestamps, and events.
macro_rules! verifier_span {
    ($($args:tt)*) => {{
        #[cfg(not(feature = "aeneas"))]
        { $crate::start_span!($($args)*) }
        #[cfg(feature = "aeneas")]
        { ((), ()) }
    }};
}
macro_rules! verifier_info {
    (if $condition:expr; $($args:tt)*) => {
        #[cfg(not(feature = "aeneas"))]
        if $condition { tracing::info!($($args)*); }
    };
    ($($args:tt)*) => {
        #[cfg(not(feature = "aeneas"))]
        tracing::info!($($args)*);
    };
}
pub(crate) use {verifier_info, verifier_span};

use traits::{Engine, pcs::PCSEngineTrait};
type CommitmentKey<E> = <<E as traits::Engine>::PCS as PCSEngineTrait<E>>::CommitmentKey;
type VerifierKey<E> = <<E as traits::Engine>::PCS as PCSEngineTrait<E>>::VerifierKey;
type Commitment<E> = <<E as Engine>::PCS as PCSEngineTrait<E>>::Commitment;
type PartialCommitment<E> = <<E as Engine>::PCS as PCSEngineTrait<E>>::PartialCommitment;
type PCS<E> = <E as Engine>::PCS;
type Blind<E> = <<E as Engine>::PCS as PCSEngineTrait<E>>::Blind;
