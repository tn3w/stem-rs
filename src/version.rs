//! Tor version parsing and comparison.
//!
//! This module provides functionality for parsing and comparing Tor version strings.
//! Tor versions follow the format specified in the
//! [Tor version-spec](https://gitweb.torproject.org/torspec.git/tree/version-spec.txt):
//! `major.minor.micro[.patch][-status][ (extra)]`
//!
//! # Conceptual Role
//!
//! The [`Version`] type enables:
//! - Parsing version strings from Tor's GETINFO responses
//! - Comparing versions to check feature availability
//! - Determining if a Tor instance meets minimum requirements
//!
//! # Version Format
//!
//! A Tor version string consists of:
//! - **major**: Major version number (required)
//! - **minor**: Minor version number (required)
//! - **micro**: Micro version number (required)
//! - **patch**: Patch level (optional, defaults to 0 for comparison)
//! - **status**: Release status tag like "alpha", "beta", "rc", "dev" (optional)
//! - **extra**: Additional info like git commit (parsed but not stored)
//!
//! # Comparison Semantics
//!
//! Versions are compared component by component:
//! 1. Major, minor, micro, patch are compared numerically
//! 2. Missing patch is treated as 0
//! 3. Status tags are compared by release priority:
//!    - `dev` < `alpha` < `beta` < `rc` < (no status/release)
//!    - Unknown status tags are treated as release versions
//!
//! # Example
//!
//! ```rust
//! use stem_rs::Version;
//!
//! // Parse version strings
//! let v1 = Version::parse("0.4.7.1-alpha").unwrap();
//! let v2 = Version::parse("0.4.7.1").unwrap();
//!
//! // Alpha versions are less than release versions
//! assert!(v1 < v2);
//!
//! // Compare against minimum requirements
//! let minimum = Version::new(0, 4, 5);
//! assert!(v1 > minimum);
//!
//! // Build versions programmatically
//! let v3 = Version::new(0, 4, 8)
//!     .with_patch(1)
//!     .with_status("beta");
//! assert_eq!(v3.to_string(), "0.4.8.1-beta");
//! ```
//!
//! # See Also
//!
//! - [`Controller::get_version`](crate::Controller::get_version) - Query Tor's version
//! - Python Stem equivalent: `stem.version.Version`

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use crate::Error;

/// A parsed Tor version with comparison support.
///
/// Represents a Tor version in the format `major.minor.micro[.patch][-status]`.
/// Versions can be parsed from strings, compared, and converted back to strings.
///
/// # Invariants
///
/// - `major`, `minor`, and `micro` are always present
/// - `patch` is `None` if not specified in the version string
/// - `status` is `None` if no status tag was present
/// - When comparing, missing `patch` is treated as 0
///
/// # Comparison
///
/// Versions implement [`Ord`] with the following semantics:
/// - Numeric components are compared in order: major → minor → micro → patch
/// - Status tags affect ordering: `dev` < `alpha` < `beta` < `rc` < release
/// - Two versions differing only by unknown status tags are considered equal
///
/// # Example
///
/// ```rust
/// use stem_rs::Version;
///
/// let alpha = Version::parse("0.4.7.1-alpha").unwrap();
/// let beta = Version::parse("0.4.7.1-beta").unwrap();
/// let release = Version::parse("0.4.7.1").unwrap();
///
/// assert!(alpha < beta);
/// assert!(beta < release);
///
/// // Missing patch is treated as 0 for ordering (but not equality)
/// let v1 = Version::parse("0.4.7").unwrap();
/// let v2 = Version::parse("0.4.7.0").unwrap();
/// use std::cmp::Ordering;
/// assert_eq!(v1.cmp(&v2), Ordering::Equal);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Version {
    /// Major version number.
    ///
    /// Historically, Tor major versions have been 0.x.y.z.
    pub major: u32,

    /// Minor version number.
    ///
    /// Incremented for significant feature releases.
    pub minor: u32,

    /// Micro version number.
    ///
    /// Incremented for smaller feature releases within a minor version.
    pub micro: u32,

    /// Patch level, if specified.
    ///
    /// Used for bug-fix releases. When comparing versions, `None` is treated as 0.
    pub patch: Option<u32>,

    /// Release status tag, if present.
    ///
    /// Common values include:
    /// - `"dev"` - Development build
    /// - `"alpha"` - Alpha release
    /// - `"beta"` - Beta release
    /// - `"rc"` or `"rc1"`, `"rc2"`, etc. - Release candidate
    /// - `None` - Stable release
    ///
    /// Status affects version comparison: dev < alpha < beta < rc < release.
    pub status: Option<String>,
}

impl Version {
    /// Creates a new version with the specified major, minor, and micro components.
    ///
    /// The patch level defaults to `None` and status defaults to `None`,
    /// representing a stable release.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::Version;
    ///
    /// let v = Version::new(0, 4, 7);
    /// assert_eq!(v.to_string(), "0.4.7");
    /// assert_eq!(v.patch, None);
    /// assert_eq!(v.status, None);
    /// ```
    pub fn new(major: u32, minor: u32, micro: u32) -> Self {
        Self {
            major,
            minor,
            micro,
            patch: None,
            status: None,
        }
    }

    /// Sets the patch level for this version.
    ///
    /// This is a builder method that consumes and returns `self`,
    /// allowing method chaining.
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::Version;
    ///
    /// let v = Version::new(0, 4, 7).with_patch(1);
    /// assert_eq!(v.patch, Some(1));
    /// assert_eq!(v.to_string(), "0.4.7.1");
    /// ```
    pub fn with_patch(mut self, patch: u32) -> Self {
        self.patch = Some(patch);
        self
    }

    /// Sets the status tag for this version.
    ///
    /// This is a builder method that consumes and returns `self`,
    /// allowing method chaining.
    ///
    /// # Status Tags and Comparison
    ///
    /// The status tag affects version comparison:
    /// - `"dev"` versions are less than `"alpha"`
    /// - `"alpha"` versions are less than `"beta"`
    /// - `"beta"` versions are less than `"rc"` (release candidate)
    /// - `"rc"` versions are less than stable releases (no status)
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::Version;
    ///
    /// let alpha = Version::new(0, 4, 7).with_status("alpha");
    /// let beta = Version::new(0, 4, 7).with_status("beta");
    /// let release = Version::new(0, 4, 7);
    ///
    /// assert!(alpha < beta);
    /// assert!(beta < release);
    /// assert_eq!(alpha.to_string(), "0.4.7-alpha");
    /// ```
    pub fn with_status(mut self, status: impl Into<String>) -> Self {
        self.status = Some(status.into());
        self
    }

    /// Parses a version string into a [`Version`].
    ///
    /// This is a convenience wrapper around [`FromStr::from_str`].
    ///
    /// # Format
    ///
    /// The version string format is: `major.minor.micro[.patch][-status][ (extra)]`
    ///
    /// - `major`, `minor`, `micro`: Required numeric components
    /// - `patch`: Optional fourth numeric component
    /// - `status`: Optional status tag after `-` (e.g., "alpha", "beta", "rc1")
    /// - `extra`: Optional parenthesized info (e.g., git commit) - parsed but not stored
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] if:
    /// - The string is empty
    /// - Numeric components cannot be parsed as `u32`
    /// - The format is otherwise invalid
    ///
    /// # Example
    ///
    /// ```rust
    /// use stem_rs::Version;
    ///
    /// // Simple version
    /// let v = Version::parse("0.4.7").unwrap();
    /// assert_eq!((v.major, v.minor, v.micro), (0, 4, 7));
    ///
    /// // Version with patch and status
    /// let v = Version::parse("0.4.7.1-alpha").unwrap();
    /// assert_eq!(v.patch, Some(1));
    /// assert_eq!(v.status, Some("alpha".to_string()));
    ///
    /// // Version with git commit info (extra info is parsed but not stored)
    /// let v = Version::parse("0.4.7.1 (git-abc123)").unwrap();
    /// assert_eq!(v.patch, Some(1));
    ///
    /// // Invalid versions
    /// assert!(Version::parse("").is_err());
    /// assert!(Version::parse("not.a.version").is_err());
    /// ```
    pub fn parse(s: &str) -> Result<Self, Error> {
        s.parse()
    }
}

/// Parses a [`Version`] from a string.
///
/// See [`Version::parse`] for format details and examples.
impl FromStr for Version {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err(Error::Parse {
                location: "version".to_string(),
                reason: "empty version string".to_string(),
            });
        }

        let (version_part, status) =
            if let Some(idx) = s.find(|c: char| !c.is_ascii_digit() && c != '.') {
                let (v, rest) = s.split_at(idx);
                let status = rest.trim_start_matches(['-', ' ']);
                (
                    v,
                    if status.is_empty() {
                        None
                    } else {
                        Some(status.to_string())
                    },
                )
            } else {
                (s, None)
            };

        let parts: Vec<&str> = version_part.split('.').collect();
        if parts.is_empty() || parts.len() > 4 {
            return Err(Error::Parse {
                location: "version".to_string(),
                reason: format!("invalid version format: {}", s),
            });
        }

        let parse_component = |part: &str, name: &str| -> Result<u32, Error> {
            part.parse().map_err(|_| Error::Parse {
                location: "version".to_string(),
                reason: format!("invalid {} component: {}", name, part),
            })
        };

        let major = parse_component(parts.first().unwrap_or(&"0"), "major")?;
        let minor = if parts.len() > 1 {
            parse_component(parts[1], "minor")?
        } else {
            0
        };
        let micro = if parts.len() > 2 {
            parse_component(parts[2], "micro")?
        } else {
            0
        };
        let patch = if parts.len() > 3 {
            Some(parse_component(parts[3], "patch")?)
        } else {
            None
        };

        Ok(Version {
            major,
            minor,
            micro,
            patch,
            status,
        })
    }
}

/// Formats the version as a string.
///
/// The output format is `major.minor.micro[.patch][-status]`.
///
/// # Example
///
/// ```rust
/// use stem_rs::Version;
///
/// let v = Version::new(0, 4, 7).with_patch(1).with_status("alpha");
/// assert_eq!(format!("{}", v), "0.4.7.1-alpha");
///
/// let v = Version::new(0, 4, 7);
/// assert_eq!(format!("{}", v), "0.4.7");
/// ```
impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.micro)?;
        if let Some(patch) = self.patch {
            write!(f, ".{}", patch)?;
        }
        if let Some(ref status) = self.status {
            write!(f, "-{}", status)?;
        }
        Ok(())
    }
}

/// Determines the comparison priority of a status tag.
///
/// Status tags are ordered as: dev (0) < alpha (1) < beta (2) < rc (3) < release/unknown (4).
/// This ordering ensures that pre-release versions sort before stable releases.
fn status_priority(status: &Option<String>) -> u8 {
    match status.as_deref() {
        None => 4,
        Some(s) => {
            let s_lower = s.to_lowercase();
            if s_lower.starts_with("dev") {
                0
            } else if s_lower.starts_with("alpha") {
                1
            } else if s_lower.starts_with("beta") {
                2
            } else if s_lower.starts_with("rc") {
                3
            } else {
                4
            }
        }
    }
}

/// Provides total ordering for versions.
///
/// Versions are compared component by component in this order:
/// 1. `major` - compared numerically
/// 2. `minor` - compared numerically
/// 3. `micro` - compared numerically
/// 4. `patch` - compared numerically (`None` treated as 0)
/// 5. `status` - compared by release priority
///
/// # Status Priority
///
/// Status tags are ordered by release maturity:
/// - `dev` < `alpha` < `beta` < `rc` < (no status)
/// - Unknown status tags are treated as release versions
///
/// # Example
///
/// ```rust
/// use stem_rs::Version;
///
/// // Numeric comparison
/// assert!(Version::parse("0.4.7").unwrap() < Version::parse("0.4.8").unwrap());
/// assert!(Version::parse("0.4.7").unwrap() < Version::parse("0.5.0").unwrap());
///
/// // Status comparison
/// assert!(Version::parse("0.4.7-dev").unwrap() < Version::parse("0.4.7-alpha").unwrap());
/// assert!(Version::parse("0.4.7-alpha").unwrap() < Version::parse("0.4.7-beta").unwrap());
/// assert!(Version::parse("0.4.7-beta").unwrap() < Version::parse("0.4.7-rc1").unwrap());
/// assert!(Version::parse("0.4.7-rc1").unwrap() < Version::parse("0.4.7").unwrap());
///
/// // Missing patch is treated as 0 for ordering
/// use std::cmp::Ordering;
/// assert_eq!(Version::parse("0.4.7").unwrap().cmp(&Version::parse("0.4.7.0").unwrap()), Ordering::Equal);
/// ```
impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.minor.cmp(&other.minor) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.micro.cmp(&other.micro) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.patch.unwrap_or(0).cmp(&other.patch.unwrap_or(0)) {
            Ordering::Equal => {}
            ord => return ord,
        }
        status_priority(&self.status).cmp(&status_priority(&other.status))
    }
}

/// Provides partial ordering for versions.
///
/// This implementation delegates to [`Ord::cmp`], so all versions are comparable.
/// See [`Ord`] implementation for comparison semantics.
impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_version() {
        let v = Version::parse("0.4.7").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 4);
        assert_eq!(v.micro, 7);
        assert_eq!(v.patch, None);
        assert_eq!(v.status, None);
    }

    #[test]
    fn test_parse_version_with_patch() {
        let v = Version::parse("0.4.7.1").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 4);
        assert_eq!(v.micro, 7);
        assert_eq!(v.patch, Some(1));
        assert_eq!(v.status, None);
    }

    #[test]
    fn test_parse_version_with_status() {
        let v = Version::parse("0.4.7.1-alpha").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 4);
        assert_eq!(v.micro, 7);
        assert_eq!(v.patch, Some(1));
        assert_eq!(v.status, Some("alpha".to_string()));
    }

    #[test]
    fn test_parse_version_with_complex_status() {
        let v = Version::parse("0.4.8.0-alpha-dev").unwrap();
        assert_eq!(v.status, Some("alpha-dev".to_string()));
    }

    #[test]
    fn test_display() {
        let v = Version::new(0, 4, 7).with_patch(1).with_status("alpha");
        assert_eq!(v.to_string(), "0.4.7.1-alpha");
    }

    #[test]
    fn test_display_no_patch() {
        let v = Version::new(0, 4, 7);
        assert_eq!(v.to_string(), "0.4.7");
    }

    #[test]
    fn test_comparison_major() {
        let v1 = Version::new(0, 4, 7);
        let v2 = Version::new(1, 0, 0);
        assert!(v1 < v2);
    }

    #[test]
    fn test_comparison_minor() {
        let v1 = Version::new(0, 4, 7);
        let v2 = Version::new(0, 5, 0);
        assert!(v1 < v2);
    }

    #[test]
    fn test_comparison_micro() {
        let v1 = Version::new(0, 4, 7);
        let v2 = Version::new(0, 4, 8);
        assert!(v1 < v2);
    }

    #[test]
    fn test_comparison_patch() {
        let v1 = Version::new(0, 4, 7).with_patch(1);
        let v2 = Version::new(0, 4, 7).with_patch(2);
        assert!(v1 < v2);
    }

    #[test]
    fn test_comparison_status_priority() {
        let dev = Version::new(0, 4, 7).with_status("dev");
        let alpha = Version::new(0, 4, 7).with_status("alpha");
        let beta = Version::new(0, 4, 7).with_status("beta");
        let rc = Version::new(0, 4, 7).with_status("rc1");
        let release = Version::new(0, 4, 7);

        assert!(dev < alpha);
        assert!(alpha < beta);
        assert!(beta < rc);
        assert!(rc < release);
    }

    #[test]
    fn test_equality() {
        let v1 = Version::new(0, 4, 7).with_patch(1).with_status("alpha");
        let v2 = Version::new(0, 4, 7).with_patch(1).with_status("alpha");
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_parse_invalid_empty() {
        assert!(Version::parse("").is_err());
    }

    #[test]
    fn test_parse_invalid_non_numeric() {
        assert!(Version::parse("abc.def.ghi").is_err());
    }

    #[test]
    fn test_version_missing_patch_equals_zero() {
        let v1 = Version::parse("0.4.7").unwrap();
        let v2 = Version::parse("0.4.7.0").unwrap();
        assert!(v1.cmp(&v2) == std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_version_with_git_extra() {
        let v = Version::parse("0.4.7.1 (git-73ff13ab3cc9570d)").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 4);
        assert_eq!(v.micro, 7);
        assert_eq!(v.patch, Some(1));
    }

    #[test]
    fn test_version_comparison_with_status() {
        let v1 = Version::parse("0.4.7.3-tag").unwrap();
        let v2 = Version::parse("0.4.7.3").unwrap();
        assert_eq!(v1.cmp(&v2), std::cmp::Ordering::Equal);

        let v_dev = Version::parse("0.4.7.3-dev").unwrap();
        let v_release = Version::parse("0.4.7.3").unwrap();
        assert!(v_dev < v_release);
    }

    #[test]
    fn test_parsing_various_components() {
        let v = Version::parse("0.1.2.3-tag").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 1);
        assert_eq!(v.micro, 2);
        assert_eq!(v.patch, Some(3));
        assert_eq!(v.status, Some("tag".to_string()));

        let v = Version::parse("0.1.2.3").unwrap();
        assert_eq!(v.patch, Some(3));
        assert_eq!(v.status, None);

        let v = Version::parse("0.1.2-tag").unwrap();
        assert_eq!(v.patch, None);
        assert_eq!(v.status, Some("tag".to_string()));

        let v = Version::parse("0.1.2").unwrap();
        assert_eq!(v.patch, None);
        assert_eq!(v.status, None);
    }

    #[test]
    fn test_parsing_empty_tag() {
        let v = Version::parse("0.1.2.3-").unwrap();
        assert_eq!(v.patch, Some(3));

        let v = Version::parse("0.1.2-").unwrap();
        assert_eq!(v.patch, None);
    }

    #[test]
    fn test_parsing_with_extra_info() {
        let v = Version::parse("0.1.2.3-tag (git-73ff13ab3cc9570d)").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 1);
        assert_eq!(v.micro, 2);
        assert_eq!(v.patch, Some(3));
        assert!(v.status.is_some());

        let v = Version::parse("0.1.2 (git-73ff13ab3cc9570d)").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 1);
        assert_eq!(v.micro, 2);
    }

    #[test]
    fn test_invalid_version_strings() {
        assert!(Version::parse("").is_err());
        assert!(Version::parse("1.2.a.4").is_err());
        assert!(Version::parse("1.2.3.a").is_err());
    }

    #[test]
    fn test_comparison_basic_incrementing() {
        assert!(Version::parse("1.1.2.3-tag").unwrap() > Version::parse("0.1.2.3-tag").unwrap());
        assert!(Version::parse("0.2.2.3-tag").unwrap() > Version::parse("0.1.2.3-tag").unwrap());
        assert!(Version::parse("0.1.3.3-tag").unwrap() > Version::parse("0.1.2.3-tag").unwrap());
        assert!(Version::parse("0.1.2.4-tag").unwrap() > Version::parse("0.1.2.3-tag").unwrap());
        assert_eq!(
            Version::parse("0.1.2.3-tag").unwrap(),
            Version::parse("0.1.2.3-tag").unwrap()
        );
    }

    #[test]
    fn test_comparison_common_tags() {
        assert!(Version::parse("0.1.2.3-beta").unwrap() > Version::parse("0.1.2.3-alpha").unwrap());
        assert!(Version::parse("0.1.2.3-rc").unwrap() > Version::parse("0.1.2.3-beta").unwrap());
    }

    #[test]
    fn test_missing_patch_equals_zero() {
        let v1 = Version::parse("0.1.2").unwrap();
        let v2 = Version::parse("0.1.2.0").unwrap();
        assert_eq!(v1.cmp(&v2), std::cmp::Ordering::Equal);

        let v1 = Version::parse("0.1.2-tag").unwrap();
        let v2 = Version::parse("0.1.2.0-tag").unwrap();
        assert_eq!(v1.cmp(&v2), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_comparison_missing_patch_or_status() {
        let v_with_tag = Version::parse("0.1.2.3-tag").unwrap();
        let v_without_tag = Version::parse("0.1.2.3").unwrap();
        assert_eq!(v_with_tag.cmp(&v_without_tag), std::cmp::Ordering::Equal);

        assert!(Version::parse("0.1.2.3-tag").unwrap() > Version::parse("0.1.2-tag").unwrap());
    }

    #[test]
    fn test_string_conversion_roundtrip() {
        let versions = ["0.1.2.3-tag", "0.1.2.3", "0.1.2"];
        for v_str in versions {
            let v = Version::parse(v_str).unwrap();
            assert_eq!(v.to_string(), v_str);
        }
    }

    #[test]
    fn test_nonversion_comparison() {
        let v = Version::parse("0.1.2.3").unwrap();
        assert_ne!(v, Version::parse("0.1.2.4").unwrap());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn version_strategy() -> impl Strategy<Value = Version> {
        (
            0u32..100,
            0u32..100,
            0u32..100,
            proptest::option::of(0u32..100),
        )
            .prop_map(|(major, minor, micro, patch)| Version {
                major,
                minor,
                micro,
                patch,
                status: None,
            })
    }

    fn version_with_status_strategy() -> impl Strategy<Value = Version> {
        let status_strategy = proptest::option::of(prop_oneof![
            Just("dev".to_string()),
            Just("alpha".to_string()),
            Just("beta".to_string()),
            Just("rc1".to_string()),
            Just("rc2".to_string()),
        ]);
        (
            0u32..100,
            0u32..100,
            0u32..100,
            proptest::option::of(0u32..100),
            status_strategy,
        )
            .prop_map(|(major, minor, micro, patch, status)| Version {
                major,
                minor,
                micro,
                patch,
                status,
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_version_roundtrip(version in version_with_status_strategy()) {
            let s = version.to_string();
            let parsed = Version::parse(&s).expect("should parse successfully");
            prop_assert_eq!(version.major, parsed.major);
            prop_assert_eq!(version.minor, parsed.minor);
            prop_assert_eq!(version.micro, parsed.micro);
            prop_assert_eq!(version.patch, parsed.patch);
            prop_assert_eq!(version.status, parsed.status);
        }

        #[test]
        fn prop_version_comparison_transitivity(
            a in version_strategy(),
            b in version_strategy(),
            c in version_strategy()
        ) {
            if a < b && b < c {
                prop_assert!(a < c, "transitivity violated: {:?} < {:?} < {:?}", a, b, c);
            }
            if a == b && b == c {
                prop_assert_eq!(a, c, "equality transitivity violated");
            }
        }

        #[test]
        fn prop_version_comparison_consistency(a in version_strategy(), b in version_strategy()) {
            let lt = a < b;
            let eq = a == b;
            let gt = a > b;
            let count = [lt, eq, gt].iter().filter(|&&x| x).count();
            prop_assert_eq!(count, 1, "exactly one comparison should be true for {:?} vs {:?}", a, b);
        }
    }
}
