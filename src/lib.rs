//! Streaming log analysis: parse web access logs and timestamped application logs in parallel and
//! summarize errors, traffic spikes, latency and timestamp anomalies.

pub mod agg;
pub mod hist;
pub mod parse;
pub mod pipeline;
pub mod summary;
pub mod time;
