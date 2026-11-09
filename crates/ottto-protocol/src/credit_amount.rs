//! Exact provider credit amounts and the one decimal scaler behind them.
//!
//! A [`CreditAmount`] is a non-negative amount in its balance's native unit
//! (credits, resets, or USD cents), kept as integer micro-units: six fractional
//! digits, never a binary float. Every provider lexeme, decimal string and
//! `{amount_minor, exponent}` money object goes through [`scale_decimal`] or
//! [`scale_minor`]; a value that is negative, malformed or above `u64` after
//! rounding is absent, never zero or saturated.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;

const MICROS_PER_UNIT: u64 = 1_000_000;
const FRACTION_DIGITS: i64 = 6;

/// A non-negative native-unit amount in micro-units (six fractional digits).
/// The largest amount is 18,446,744,073,709.551615 native units.
///
/// On the wire a whole amount is a JSON integer of native units, so integer
/// bodies are byte-identical to the older `u64` field, and a fractional amount
/// is a decimal string with at most six fractional digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CreditAmount(u64);

impl CreditAmount {
    pub const ZERO: Self = Self(0);

    /// `units` whole native units; `None` above the representable range.
    pub fn whole(units: u64) -> Option<Self> {
        units.checked_mul(MICROS_PER_UNIT).map(Self)
    }

    /// A decimal lexeme in native units, rounded half-even to six digits.
    pub fn from_decimal(text: &str) -> Option<Self> {
        scale_decimal(text, FRACTION_DIGITS).map(Self)
    }

    pub const fn micros(self) -> u64 {
        self.0
    }

    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    /// The amount in whole native units, when it has no fraction.
    pub const fn whole_units(self) -> Option<u64> {
        if self.0 % MICROS_PER_UNIT == 0 {
            Some(self.0 / MICROS_PER_UNIT)
        } else {
            None
        }
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// `self − other`, floored at zero.
    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// A JSON value's exact text: a number lexeme or a quoted decimal string.
    fn from_json_text(text: &str) -> Option<Self> {
        if text.starts_with('"') {
            Self::from_decimal(&serde_json::from_str::<String>(text).ok()?)
        } else {
            Self::from_decimal(text)
        }
    }

    /// `deserialize_with` for an optional amount field. The value's raw JSON
    /// text is parsed exactly (an older daemon's integer, or a decimal
    /// string); an invalid or out-of-range amount makes only that field absent.
    pub fn deserialize_optional<'de, D>(deserializer: D) -> Result<Option<Self>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Option::<Box<RawValue>>::deserialize(deserializer)?
            .and_then(|raw| Self::from_json_text(raw.get())))
    }
}

impl Serialize for CreditAmount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (units, micros) = (self.0 / MICROS_PER_UNIT, self.0 % MICROS_PER_UNIT);
        if micros == 0 {
            return serializer.serialize_u64(units);
        }
        let fraction = format!("{micros:06}");
        serializer.serialize_str(&format!("{units}.{}", fraction.trim_end_matches('0')))
    }
}

/// The one exact decimal scaler: `text` × 10^`shift`, rounded half-even to an
/// integer. `text` is an unsigned decimal (`12`, `0.40`, `1.5e3`); surrounding
/// whitespace is ignored. A sign, any other shape, or a result above `u64`
/// gives `None`.
pub fn scale_decimal(text: &str, shift: i64) -> Option<u64> {
    let text = text.trim();
    let (mantissa, exponent) = match text.find(['e', 'E']) {
        Some(at) => (&text[..at], text[at + 1..].parse::<i64>().ok()?),
        None => (text, 0),
    };
    let (whole, fraction) = match mantissa.split_once('.') {
        Some((whole, fraction)) if !fraction.is_empty() => (whole, fraction),
        Some(_) => return None,
        None => (mantissa, ""),
    };
    let digits = whole.bytes().chain(fraction.bytes());
    if whole.is_empty() || !digits.clone().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let exponent = exponent
        .checked_add(shift)?
        .checked_sub(i64::try_from(fraction.len()).ok()?)?;
    scale_digits(digits, whole.len() + fraction.len(), exponent)
}

/// An integer count of minor units × 10^`shift`, through the same scaler
/// (`{amount_minor, exponent}` money objects).
pub fn scale_minor(minor: u64, shift: i64) -> Option<u64> {
    let digits = minor.to_string();
    scale_digits(digits.bytes(), digits.len(), shift)
}

/// ASCII `digits` × 10^`exponent`, rounded half-even to an integer: an exact
/// tie of 5 rounds to the even neighbour, and any nonzero digit after the
/// first discarded 5 rounds up. Overflow is checked after the carry.
fn scale_digits(digits: impl Iterator<Item = u8>, count: usize, exponent: i64) -> Option<u64> {
    let keep = i64::try_from(count).ok()?.checked_add(exponent)?;
    let (mut value, mut first_dropped, mut tail) = (0_u64, 0_u8, false);
    for (index, digit) in (0_i64..).zip(digits) {
        let digit = digit - b'0';
        if index < keep {
            value = value.checked_mul(10)?.checked_add(u64::from(digit))?;
        } else if index == keep {
            first_dropped = digit;
        } else {
            tail |= digit != 0;
        }
    }
    for _ in 0..exponent.max(0) {
        if value == 0 {
            break;
        }
        value = value.checked_mul(10)?;
    }
    if first_dropped > 5 || (first_dropped == 5 && (tail || value % 2 == 1)) {
        value = value.checked_add(1)?;
    }
    Some(value)
}
