//! Crash-restart policy: exponential backoff, and give up (=> report
//! degraded, never a green status) when crashing in a loop.

use std::collections::VecDeque;

#[derive(Debug, PartialEq)]
pub enum Action {
    Restart { delay_ms: u64 },
    GiveUp,
}

pub struct Supervisor {
    crashes: VecDeque<u64>,
    max_in_window: usize,
    window_ms: u64,
    base_ms: u64,
    cap_ms: u64,
}

impl Supervisor {
    pub fn new() -> Self {
        Self { crashes: VecDeque::new(), max_in_window: 5, window_ms: 60_000, base_ms: 1_000, cap_ms: 30_000 }
    }

    pub fn on_exit(&mut self, now_ms: u64) -> Action {
        self.crashes.push_back(now_ms);
        while self.crashes.front().map_or(false, |&t| now_ms.saturating_sub(t) > self.window_ms) {
            self.crashes.pop_front();
        }
        let n = self.crashes.len();
        if n > self.max_in_window {
            return Action::GiveUp;
        }
        Action::Restart { delay_ms: (self.base_ms << (n - 1).min(10)).min(self.cap_ms) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backoff_grows_then_gives_up_then_recovers() {
        let mut s = Supervisor::new();
        assert_eq!(s.on_exit(0), Action::Restart { delay_ms: 1000 });
        assert_eq!(s.on_exit(1), Action::Restart { delay_ms: 2000 });
        assert_eq!(s.on_exit(2), Action::Restart { delay_ms: 4000 });
        assert_eq!(s.on_exit(3), Action::Restart { delay_ms: 8000 });
        assert_eq!(s.on_exit(4), Action::Restart { delay_ms: 16000 });
        assert_eq!(s.on_exit(5), Action::GiveUp);
        // long after the window, a single crash restarts normally again
        assert_eq!(s.on_exit(1_000_000), Action::Restart { delay_ms: 1000 });
    }
}
