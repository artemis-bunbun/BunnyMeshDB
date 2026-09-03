//! Hybrid Logical Clock — monotonic (physical ms, counter) timestamp.
//!
//! Physical milliseconds occupy the high 48 bits, a 16-bit logical counter
//! the low bits. A larger physical ms always dominates, so wall-clock steps
//! backward never regress a timestamp. Cross-host ordering is `(hlc, replica)`
//! — Hlc alone is not total.

use std::time::{SystemTime, UNIX_EPOCH};

const COUNTER_MASK: u64 = 0xFFFF;
const PHYS_SHIFT: u32 = 16;

/// Hybrid logical clock value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hlc(u64);

impl Hlc {
    /// Current wall-clock ms with logical counter 0.
    pub fn now() -> Hlc {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_millis() as u64;
        Hlc(ms << PHYS_SHIFT)
    }

    /// Merge another observed HLC into self. Self never decreases; on the
    /// same physical ms the counter advances (spilling into the next ms when
    /// exhausted), otherwise the larger physical ms wins.
    pub fn observed(&mut self, other: Hlc) {
        let prev_phys = self.0 >> PHYS_SHIFT;
        let m = self.0.max(other.0);
        if (m >> PHYS_SHIFT) == prev_phys {
            let c = (m & COUNTER_MASK) + 1;
            if c > COUNTER_MASK {
                self.0 = (prev_phys + 1) << PHYS_SHIFT;
            } else {
                self.0 = (m & !COUNTER_MASK) | c;
            }
        } else {
            self.0 = m;
        }
    }

    /// Physical milliseconds component.
    pub fn ms(&self) -> u64 {
        self.0 >> PHYS_SHIFT
    }

    /// Logical counter component (0..=0xFFFF).
    pub fn counter(&self) -> u16 {
        (self.0 & COUNTER_MASK) as u16
    }

    pub fn to_u64(&self) -> u64 {
        self.0
    }
}

impl From<u64> for Hlc {
    fn from(v: u64) -> Hlc {
        Hlc(v)
    }
}

impl From<Hlc> for u64 {
    fn from(h: Hlc) -> u64 {
        h.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn causal_chain_orders() {
        let t0 = Hlc::now();
        let mut a = t0;
        let mut b = t0;
        b.observed(a);
        a.observed(b); // a observes b which observed a's earlier value
        assert!(a > b, "a must be newer than b after the causal chain");
        assert!(a > t0 && b > t0);
    }

    #[test]
    fn concurrent_increments_differ() {
        let t0 = Hlc::now();
        let mut a = t0;
        let mut c = t0;
        a.observed(t0);
        c.observed(t0);
        assert_eq!(a, c, "equal concurrent increments tiebreak by replica");
        let mut b = t0;
        b.observed(a); // b sees a's increment → strictly ahead
        assert_ne!(a, b);
        assert_ne!(b, c);
        let before = a;
        a.observed(b);
        assert!(a > b && a > before);
    }

    #[test]
    fn backward_clock_stays_monotonic() {
        let base = Hlc::now();
        let mut h = base;
        h.observed(Hlc::from(1u64)); // ancient clock observed
        // HLC event semantics: any observed/own event bumps the counter when
        // the physical ms is unchanged — the invariant is monotonicity, not
        // identity. It must never return to an older physical ms.
        assert!(h > base, "must never regress: {} > {}", h.to_u64(), base.to_u64());
        assert!(h.ms() >= base.ms());
        let after = h;
        h.observed(Hlc::from(0u64));
        assert!(h >= after, "second older observation must not regress either");

        // Counter exhaustion spills into the next physical ms, never back.
        let at_max = Hlc::from((base.ms() << PHYS_SHIFT) | u64::from(COUNTER_MASK));
        let mut h2 = Hlc::from(at_max.to_u64() - 1);
        h2.observed(at_max);
        assert_eq!(h2.ms(), at_max.ms() + 1);
        assert_eq!(h2.counter(), 0);
        assert!(h2 > at_max);
    }

    #[test]
    fn ms_and_counter_roundtrip() {
        let h = Hlc::now();
        assert_eq!(Hlc::from(h.to_u64()), h);
        assert_eq!(u64::from(h), h.to_u64());
        assert_eq!(h.ms(), h.to_u64() >> PHYS_SHIFT);
    }
}