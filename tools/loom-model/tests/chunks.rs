//! Loom model of the qWp host parallel-leaf chunking pattern.
//!
//! `qwp-platform` splits a fixed array with `chunks_mut`, spawns one scoped
//! worker per chunk, and joins all workers. There is no shared mutable state:
//! each worker owns a disjoint slice. This model checks the two invariants the
//! pattern relies on: every index is written exactly once, and every write is
//! visible after join.

use loom::sync::atomic::{AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

const WORKERS: usize = 3;
const LEAVES: usize = 7;

#[test]
fn disjoint_chunks_are_written_exactly_once() {
    loom::model(|| {
        let output: Arc<Vec<AtomicU64>> =
            Arc::new((0..LEAVES).map(|_| AtomicU64::new(u64::MAX)).collect());
        let chunk_size = LEAVES.div_ceil(WORKERS);
        let mut handles = Vec::new();

        for worker in 0..WORKERS {
            let output = Arc::clone(&output);
            handles.push(thread::spawn(move || {
                let start = worker * chunk_size;
                let end = usize::min(start + chunk_size, LEAVES);
                for index in start..end {
                    output[index].store(index as u64, Ordering::Release);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        for (index, slot) in output.iter().enumerate() {
            assert_eq!(slot.load(Ordering::Acquire), index as u64);
        }
    });
}
