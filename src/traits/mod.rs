//! This module defines various traits required by the users of the library to implement.
use core::fmt::Debug;
use ff::PrimeField;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

pub mod circuit;
pub mod pcs;
pub mod snark;
pub mod transcript;

use pcs::PCSEngineTrait;
use transcript::{TranscriptEngineTrait, TranscriptReprTrait};

/// Represents an element of a group
/// This is currently tailored for an elliptic curve group
// PrimeFieldBits makes Charon extract Bitvec's additional types and trait
// requirements whenever it extracts Group or Engine. That unused dependency
// made verifier extraction exceed its time limit. These interfaces only need
// PrimeField operations, so require those directly.
pub trait Group: Clone + Copy + Debug + Send + Sync + Sized + Eq + PartialEq {
  /// A type representing an element of the base field of the group
  type Base: PrimeField + Serialize + for<'de> Deserialize<'de>;

  /// A type representing an element of the scalar field of the group
  type Scalar: PrimeField + PrimeFieldExt + Send + Sync + Serialize + for<'de> Deserialize<'de>;

  /// Returns A, B, the order of the group, the size of the base field as big integers
  fn group_params() -> (Self::Base, Self::Base, BigInt, BigInt);
}

/// A collection of engines that are required by the library
pub trait Engine: Clone + Copy + Debug + Send + Sync + Sized + Eq + PartialEq {
  /// A type representing an element of the base field of the group
  type Base: PrimeField + TranscriptReprTrait<Self::GE> + Serialize + for<'de> Deserialize<'de>;

  /// A type representing an element of the scalar field of the group
  type Scalar: PrimeField
    + PrimeFieldExt
    + Send
    + Sync
    + TranscriptReprTrait<Self::GE>
    + Serialize
    + for<'de> Deserialize<'de>;

  /// A type that represents an element of the group
  type GE: Group<Base = Self::Base, Scalar = Self::Scalar> + Serialize + for<'de> Deserialize<'de>;

  /// A type that provides a generic Fiat-Shamir transcript to be used when externalizing proofs
  type TE: TranscriptEngineTrait<Self>;

  /// A type that defines a commitment engine over scalars in the group
  type PCS: PCSEngineTrait<Self>;
}

/// Defines additional methods on `PrimeField` objects
pub trait PrimeFieldExt: PrimeField {
  /// Returns a scalar representing the bytes
  fn from_uniform(bytes: &[u8]) -> Self;
}
