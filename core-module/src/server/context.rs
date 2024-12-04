//! The `Server Context` in this module holds the common state across all servers
use std::fs;
use std::sync::atomic::{AtomicSize, Ordering};
use std::sync::Arc;

use derive_more::{Display, Error, From};

use crate::