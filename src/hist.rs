//! Mergeable latency histogram with bounded relative error.
//!
//! Values land in geometric buckets (ratio 1.02), so any quantile is within about 1% of the true
//! value, memory is a few hundred buckets however many values arrive, and two histograms merge by
//! adding counts. That is what lets worker threads each keep their own and combine at the end.

use std::collections::BTreeMap;

const GAMMA: f64 = 1.02;
/// Anything at or below this many seconds shares the lowest bucket.
const FLOOR: f64 = 1e-6;

#[derive(Clone, Debug, Default)]
pub struct LogHist {
    buckets: BTreeMap<i32, u64>,
    count: u64,
    max: f64,
}

impl LogHist {
    pub fn add(&mut self, v: f64) {
        if !v.is_finite() || v < 0.0 {
            return;
        }
        let idx = (v.max(FLOOR).ln() / GAMMA.ln()).ceil() as i32;
        *self.buckets.entry(idx).or_insert(0) += 1;
        self.count += 1;
        self.max = self.max.max(v);
    }

    pub fn merge(&mut self, other: &LogHist) {
        for (k, c) in &other.buckets {
            *self.buckets.entry(*k).or_insert(0) += c;
        }
        self.count += other.count;
        self.max = self.max.max(other.max);
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn max(&self) -> f64 {
        self.max
    }

    /// Value at quantile `q` in 0..=1, or `None` when empty.
    pub fn quantile(&self, q: f64) -> Option<f64> {
        if self.count == 0 {
            return None;
        }
        let rank = ((q.clamp(0.0, 1.0) * self.count as f64).ceil() as u64).max(1);
        let mut seen = 0;
        for (idx, c) in &self.buckets {
            seen += c;
            if seen >= rank {
                // The bucket spans (gamma^(idx-1), gamma^idx]; report its midpoint, never above max.
                let hi = GAMMA.powi(*idx);
                return Some((hi * 2.0 / (1.0 + GAMMA)).min(self.max));
            }
        }
        Some(self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(sorted: &[f64], q: f64) -> f64 {
        sorted[((q * sorted.len() as f64).ceil() as usize).max(1) - 1]
    }

    #[test]
    fn quantiles_are_within_two_percent_of_exact() {
        // Heavy-tailed, deterministic values from 1 ms to several seconds.
        let mut x = 12345u64;
        let mut vals: Vec<f64> = (0..50_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                0.001 * (1.0 + (x % 100_000) as f64 / 100.0).powf(1.5)
            })
            .collect();
        let mut h = LogHist::default();
        vals.iter().for_each(|v| h.add(*v));
        vals.sort_by(|a, b| a.total_cmp(b));
        for q in [0.5, 0.9, 0.95, 0.99, 0.999] {
            let (got, want) = (h.quantile(q).unwrap(), exact(&vals, q));
            assert!((got - want).abs() / want < 0.02, "q{q}: {got} vs {want}");
        }
        assert_eq!(h.max(), *vals.last().unwrap());
    }

    #[test]
    fn merging_equals_adding_everything_to_one() {
        let (mut a, mut b, mut whole) = (LogHist::default(), LogHist::default(), LogHist::default());
        for i in 1..=2000 {
            let v = i as f64 / 100.0;
            whole.add(v);
            if i % 3 == 0 { a.add(v) } else { b.add(v) }
        }
        a.merge(&b);
        assert_eq!(a.count(), whole.count());
        for q in [0.1, 0.5, 0.99] {
            assert_eq!(a.quantile(q), whole.quantile(q));
        }
    }

    #[test]
    fn empty_and_invalid_input() {
        let mut h = LogHist::default();
        assert_eq!(h.quantile(0.5), None);
        h.add(f64::NAN);
        h.add(-1.0);
        h.add(f64::INFINITY);
        assert_eq!(h.count(), 0);
        h.add(0.0);
        assert_eq!(h.count(), 1);
        assert!(h.quantile(1.0).unwrap() <= 1e-6 + f64::EPSILON);
    }
}
