use mio::{Events, Poll, Token, Waker};
use slog::info;
use slog::Logger;
use std::fmt::Debug;
use std::sync::atomic::AtomicBool;
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use teaparty::maybe_log;

pub struct TaskResult<T> {
    #[allow(unused)]
    pub result: T,
    pub next: Option<Instant>,
}

pub struct Task<T> {
    pub when: Instant,
    pub what: Box<dyn Fn() -> TaskResult<T> + Send>,
}

pub struct Asymmetry<T> {
    tasks: Arc<Mutex<Vec<Task<T>>>>,
    poll: Arc<Mutex<Poll>>,
    waker: Arc<Mutex<Waker>>,
    cancelled: Arc<AtomicBool>,
    logger: Option<Logger>,
}

impl<T> Debug for Asymmetry<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Asymmetry!")
    }
}

const WAKER_TOKEN: Token = Token(1);

impl<T> Asymmetry<T> {
    pub fn new(logger: Option<Logger>) -> Self {
        let poll = Poll::new().expect("Should have been able to make a poll.");
        let waker = Arc::new(Mutex::new(
            Waker::new(poll.registry(), WAKER_TOKEN).expect("Should have been able to make waker."),
        ));
        Asymmetry {
            poll: Arc::new(Mutex::new(poll)),
            tasks: Arc::new(Mutex::new(vec![])),
            waker,
            cancelled: Arc::new(AtomicBool::new(false)),
            logger,
        }
    }

    pub fn wait_for_next(&self) -> Result<(), std::io::Error> {
        let next_time = {
            let tasks = self.tasks.lock().unwrap();
            if tasks.is_empty() {
                None
            } else {
                Some(tasks[0].when)
            }
        };

        // If there is a next_time, now we wait.
        if let Some(next_time) = next_time {
            let sleep_duration = next_time - Instant::now();

            let mut events = Events::with_capacity(1);

            let mut poll = self.poll.lock().unwrap();
            maybe_log!(self.logger, info, "About to sleep for {:?}", sleep_duration);
            poll.poll(&mut events, Some(sleep_duration))?;
        }

        Ok(())
    }

    pub fn next_time(&self) -> Option<Instant> {
        let tasks = self.tasks.lock().unwrap();
        if tasks.is_empty() {
            return None;
        }
        Some(tasks[0].when)
    }

    pub fn add(&self, new_task: Task<T>) {
        {
            let mut tasks = self.tasks.lock().unwrap();
            tasks.push(new_task);
            // An index to the leaf.
            let index = tasks.len() - 1;
            Self::fixup(&mut tasks, index);
        }
        self.wakeup();
    }

    fn fixdown(tasks: &mut [Task<T>], mut index: usize) {
        while (index * 2 + 1) < tasks.len() {
            let mut new_index = index;
            let left_child = index * 2 + 1;
            let right_child = std::cmp::min(index * 2 + 2, tasks.len() - 1);
            if tasks[index].when >= tasks[left_child].when {
                new_index = left_child;
            }
            if tasks[new_index].when >= tasks[right_child].when {
                new_index = right_child;
            }
            if index == new_index {
                break;
            }

            // Otherwise, swap!
            tasks.swap(new_index, index);
            index = new_index;
        }
    }

    fn fixup(tasks: &mut [Task<T>], mut index: usize) {
        while index != 0 {
            let parent_index = index / 2;
            if tasks[parent_index].when <= tasks[index].when {
                break;
            }

            // Otherwise, swap!
            tasks.swap(parent_index, index);
            index = parent_index;
        }
    }

    ///
    /// Never called when a runtime is waiting.
    pub fn complete(&self) -> Option<Task<T>> {
        let mut tasks = self.tasks.lock().unwrap();

        if tasks.is_empty() {
            return None;
        }

        let last_index = tasks.len() - 1;
        tasks.swap(0, last_index);

        let completed = tasks.pop().unwrap();

        Self::fixdown(&mut tasks, 0);

        Some(completed)
    }

    fn wakeup(&self) {
        self.waker
            .lock()
            .unwrap()
            .wake()
            .expect("Should have been able to wake up the runtime.");
    }

    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn run(&self) {
        loop {
            if self.cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                maybe_log!(
                    self.logger,
                    info,
                    "A runtime ({:?}) has been asked to stop.",
                    self
                );
                break;
            }
            self.wait_for_next().unwrap();

            // Is there an event waiting?
            if let Some(next_time) = self.next_time() {
                // Is it time to do that event?
                if next_time < Instant::now() {
                    // Let's do it!
                    if let Some(task) = self.complete() {
                        // Execute the task.
                        let result = (task.what)();

                        // If it said that it wants to be done again, re-enable it.
                        if let Some(next) = result.next {
                            self.add(Task {
                                when: next,
                                what: task.what,
                            });
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test_asymmetry {
    use super::{Asymmetry, Task};
    use std::time::Instant;

    #[test]
    fn test_reverse() {
        let asymm = Asymmetry::<usize>::new(None);

        let t_time = Instant::now() + std::time::Duration::from_secs(10);
        let t2_time = Instant::now() + std::time::Duration::from_secs(5);
        let t3_time = Instant::now() + std::time::Duration::from_secs(2);
        let t4_time = Instant::now() + std::time::Duration::from_secs(1);
        let t5_time = Instant::now() + std::time::Duration::from_secs(0);
        let t = Task::<usize> {
            when: t_time,
            what: Box::new(move || {
                println!("Hello!");
                crate::asymmetry::TaskResult {
                    result: 32,
                    next: None,
                }
            }),
        };
        let t2 = Task::<usize> {
            when: t2_time,
            what: Box::new(move || {
                println!("Hello!");
                crate::asymmetry::TaskResult {
                    result: 32,
                    next: None,
                }
            }),
        };
        let t3 = Task::<usize> {
            when: t3_time,
            what: Box::new(move || {
                println!("Hello!");
                crate::asymmetry::TaskResult {
                    result: 32,
                    next: None,
                }
            }),
        };
        let t4 = Task::<usize> {
            when: t4_time,
            what: Box::new(move || {
                println!("Hello!");
                crate::asymmetry::TaskResult {
                    result: 32,
                    next: None,
                }
            }),
        };
        let t5 = Task::<usize> {
            when: t5_time,
            what: Box::new(move || {
                println!("Hello!");
                crate::asymmetry::TaskResult {
                    result: 32,
                    next: None,
                }
            }),
        };

        asymm.add(t);
        asymm.add(t2);
        asymm.add(t3);
        asymm.add(t4);
        asymm.add(t5);
        let complete = asymm.complete();
        assert!(complete.unwrap().when == t5_time);
        let complete = asymm.complete();
        assert!(complete.unwrap().when == t4_time);
        let complete = asymm.complete();
        assert!(complete.unwrap().when == t3_time);
        let complete = asymm.complete();
        assert!(complete.unwrap().when == t2_time);
        let complete = asymm.complete();
        assert!(complete.unwrap().when == t_time);
    }

    #[test]
    fn test_forward() {
        let asymm = Asymmetry::<usize>::new(None);

        let t_time = Instant::now() + std::time::Duration::from_secs(0);
        let t2_time = Instant::now() + std::time::Duration::from_secs(1);
        let t3_time = Instant::now() + std::time::Duration::from_secs(2);
        let t4_time = Instant::now() + std::time::Duration::from_secs(5);
        let t5_time = Instant::now() + std::time::Duration::from_secs(10);
        let t = Task::<usize> {
            when: t_time,
            what: Box::new(move || {
                println!("Hello!");
                crate::asymmetry::TaskResult {
                    result: 32,
                    next: None,
                }
            }),
        };
        let t2 = Task::<usize> {
            when: t2_time,
            what: Box::new(move || {
                println!("Hello!");
                crate::asymmetry::TaskResult {
                    result: 32,
                    next: None,
                }
            }),
        };
        let t3 = Task::<usize> {
            when: t3_time,
            what: Box::new(move || {
                println!("Hello!");
                crate::asymmetry::TaskResult {
                    result: 32,
                    next: None,
                }
            }),
        };
        let t4 = Task::<usize> {
            when: t4_time,
            what: Box::new(move || {
                println!("Hello!");
                crate::asymmetry::TaskResult {
                    result: 32,
                    next: None,
                }
            }),
        };
        let t5 = Task::<usize> {
            when: t5_time,
            what: Box::new(move || {
                println!("Hello!");
                crate::asymmetry::TaskResult {
                    result: 32,
                    next: None,
                }
            }),
        };

        asymm.add(t);
        asymm.add(t2);
        asymm.add(t3);
        asymm.add(t4);
        asymm.add(t5);
        let complete = asymm.complete();
        assert!(complete.unwrap().when == t_time);
        let complete = asymm.complete();
        assert!(complete.unwrap().when == t2_time);
        let complete = asymm.complete();
        assert!(complete.unwrap().when == t3_time);
        let complete = asymm.complete();
        assert!(complete.unwrap().when == t4_time);
        let complete = asymm.complete();
        assert!(complete.unwrap().when == t5_time);
    }
}
