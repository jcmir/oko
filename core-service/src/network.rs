use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NetworkState {
    Green,  // Online and connected to server
    Yellow, // Offline, but service is running
    Red,    // Error or disconnected (watchdog uses this when core is dead)
}

pub struct NetworkManager {
    state: Arc<Mutex<NetworkState>>,
    machine_id: String,
}

impl NetworkManager {
    pub fn new() -> Self {
        NetworkManager {
            state: Arc::new(Mutex::new(NetworkState::Yellow)), // Default to Yellow on startup until connection is established
            machine_id: String::from("PENDING_REGISTRATION"),
        }
    }

    pub fn get_state(&self) -> NetworkState {
        let guard = self.state.lock().unwrap();
        *guard
    }

    pub fn set_state(&self, new_state: NetworkState) {
        let mut guard = self.state.lock().unwrap();
        *guard = new_state;
    }

    pub fn get_machine_id(&self) -> String {
        self.machine_id.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_manager_initial_state() {
        let manager = NetworkManager::new();
        assert_eq!(manager.get_state(), NetworkState::Yellow);
        assert_eq!(manager.get_machine_id(), "PENDING_REGISTRATION");
    }

    #[test]
    fn test_network_state_transitions() {
        let manager = NetworkManager::new();

        manager.set_state(NetworkState::Green);
        assert_eq!(manager.get_state(), NetworkState::Green);

        manager.set_state(NetworkState::Red);
        assert_eq!(manager.get_state(), NetworkState::Red);
    }
}
