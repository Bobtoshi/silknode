//! Seed-only, process-local admission and actual TCP egress budgets.
use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const MAX_CONNECTIONS: usize = 3;
const PEER_CONNECTIONS: usize = 2;
const PEER_STARTS: usize = 16;
const GLOBAL_STARTS: usize = 64;
const MAX_PEERS: usize = 128;
const WINDOW: Duration = Duration::from_secs(60);
const MIB: usize = 1024 * 1024;
const CONNECTION_BYTES: usize = 4 * MIB;
const PEER_BYTES: usize = 4 * MIB;
const GLOBAL_BYTES: usize = 16 * MIB;

struct Window {
    began: Instant,
    starts: usize,
    bytes: usize,
}
impl Window {
    fn new(began: Instant) -> Self {
        Self {
            began,
            starts: 0,
            bytes: 0,
        }
    }
    fn refresh(&mut self, now: Instant) {
        if now.saturating_duration_since(self.began) >= WINDOW {
            *self = Self::new(now);
        }
    }
}
struct Peer {
    active: usize,
    window: Window,
}
struct State {
    active: usize,
    global: Window,
    peers: HashMap<IpAddr, Peer>,
}
#[derive(Clone)]
pub struct Limits(Arc<Mutex<State>>);
impl Limits {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            active: 0,
            global: Window::new(Instant::now()),
            peers: HashMap::new(),
        })))
    }
    pub fn admit(&self, ip: IpAddr, now: Instant) -> Option<Permit> {
        let ip = match ip {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        let mut state = self.0.lock().ok()?;
        state.global.refresh(now);
        if state.active >= MAX_CONNECTIONS || state.global.starts >= GLOBAL_STARTS {
            return None;
        }
        // Do not evict an IP's still-current spent budget when its socket closes.
        state.peers.retain(|_, peer| {
            peer.active != 0 || now.saturating_duration_since(peer.window.began) < WINDOW
        });
        if !state.peers.contains_key(&ip) && state.peers.len() >= MAX_PEERS {
            return None;
        }
        let peer = state.peers.entry(ip).or_insert_with(|| Peer {
            active: 0,
            window: Window::new(now),
        });
        peer.window.refresh(now);
        if peer.active >= PEER_CONNECTIONS || peer.window.starts >= PEER_STARTS {
            return None;
        }
        peer.active += 1;
        peer.window.starts += 1;
        state.active += 1;
        state.global.starts += 1;
        Some(Permit {
            limits: self.clone(),
            ip,
            began: now,
            bytes: 0,
        })
    }
}
pub struct Permit {
    limits: Limits,
    ip: IpAddr,
    pub began: Instant,
    bytes: usize,
}
impl Permit {
    pub fn charge(&mut self, bytes: usize, now: Instant) -> io::Result<()> {
        let refused = || io::Error::other("seed egress budget exhausted");
        let mut state = self.limits.0.lock().map_err(|_| refused())?;
        state.global.refresh(now);
        let global_left = GLOBAL_BYTES - state.global.bytes;
        let peer = state.peers.get_mut(&self.ip).ok_or_else(refused)?;
        peer.window.refresh(now);
        if bytes > CONNECTION_BYTES - self.bytes
            || bytes > PEER_BYTES - peer.window.bytes
            || bytes > global_left
        {
            return Err(refused());
        }
        // Reserve before writing. Partial/failed writes are conservatively charged;
        // no other socket can spend the same allowance. Include TLS and framing.
        peer.window.bytes += bytes;
        state.global.bytes += bytes;
        self.bytes += bytes;
        Ok(())
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.limits.0.lock() {
            state.active -= 1;
            if let Some(peer) = state.peers.get_mut(&self.ip) {
                peer.active -= 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_release_slots_but_keep_spent_rates_and_egress() {
        let limits = Limits::new();
        let now = Instant::now();
        let a: IpAddr = "127.0.0.1".parse().unwrap();
        let b: IpAddr = "127.0.0.2".parse().unwrap();
        let c: IpAddr = "127.0.0.3".parse().unwrap();
        let mut first = limits.admit(a, now).unwrap();
        let second = limits.admit(a, now).unwrap();
        assert!(limits.admit(a, now).is_none());
        assert!(
            limits
                .admit("::ffff:127.0.0.1".parse().unwrap(), now)
                .is_none()
        );
        let third = limits.admit(b, now).unwrap();
        assert!(limits.admit(c, now).is_none());
        first.charge(CONNECTION_BYTES, now).unwrap();
        assert!(first.charge(1, now).is_err());
        drop(first);
        let mut replacement = limits.admit(a, now).unwrap();
        assert!(replacement.charge(1, now).is_err());
        drop((replacement, second, third));
        for i in 2..=4 {
            let ip = format!("127.0.0.{i}").parse().unwrap();
            limits
                .admit(ip, now)
                .unwrap()
                .charge(PEER_BYTES, now)
                .unwrap();
        }
        assert!(limits.admit(c, now).unwrap().charge(1, now).is_err());
        for _ in 3..PEER_STARTS {
            drop(limits.admit(a, now).unwrap());
        }
        assert!(limits.admit(a, now).is_none());
        while limits.0.lock().unwrap().global.starts < GLOBAL_STARTS {
            drop(
                limits
                    .admit("127.0.0.5".parse().unwrap(), now)
                    .or_else(|| limits.admit("127.0.0.6".parse().unwrap(), now))
                    .or_else(|| limits.admit("127.0.0.7".parse().unwrap(), now))
                    .unwrap(),
            );
        }
        assert!(limits.admit("127.0.0.8".parse().unwrap(), now).is_none());
        let later = now + WINDOW;
        let mut fresh = limits.admit(a, later).unwrap();
        fresh.charge(PEER_BYTES, later).unwrap();
        assert_eq!(limits.0.lock().unwrap().active, 1);
        drop(fresh);
        assert_eq!(limits.0.lock().unwrap().active, 0);
    }
}
