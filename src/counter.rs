use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Activity counter data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityCounter {
    pub count: u64,
}

impl Default for ActivityCounter {
    fn default() -> Self {
        Self { count: 0 }
    }
}

/// Activity counter manager with file persistence
pub struct ActivityCounterManager {
    counter: Arc<Mutex<ActivityCounter>>,
    file_path: PathBuf,
}

impl ActivityCounterManager {
    /// Create a new counter manager with file path
    pub fn new(file_path: impl Into<PathBuf>) -> Result<Self> {
        let file_path: PathBuf = file_path.into();
        let counter = Self::load_from_file(&file_path)?;

        Ok(Self {
            counter: Arc::new(Mutex::new(counter)),
            file_path,
        })
    }

    /// Load counter from file, create default if file doesn't exist
    fn load_from_file(file_path: &PathBuf) -> Result<ActivityCounter> {
        if file_path.exists() {
            let content = fs::read_to_string(file_path).with_context(|| format!("Failed to read counter file: {}", file_path.display()))?;
            let counter: ActivityCounter =
                serde_json::from_str(&content).with_context(|| format!("Failed to parse counter file: {}", file_path.display()))?;
            tracing::info!("Loaded activity counter: {} from {}", counter.count, file_path.display());
            Ok(counter)
        } else {
            tracing::info!("Counter file not found, creating new counter at {}", file_path.display());
            let counter = ActivityCounter::default();
            // Create parent directory if it doesn't exist
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent).with_context(|| format!("Failed to create directory: {}", parent.display()))?;
            }
            // Save initial counter
            let content = serde_json::to_string_pretty(&counter).context("Failed to serialize counter")?;
            fs::write(file_path, content).with_context(|| format!("Failed to write counter file: {}", file_path.display()))?;
            Ok(counter)
        }
    }

    /// Save counter to file
    fn save_to_file(&self, counter: &ActivityCounter) -> Result<()> {
        let content = serde_json::to_string_pretty(counter).context("Failed to serialize counter")?;
        fs::write(&self.file_path, content).with_context(|| format!("Failed to write counter file: {}", self.file_path.display()))?;
        Ok(())
    }

    /// Increment counter and return new value
    pub fn increment(&self) -> Result<u64> {
        let mut counter = self.counter.lock().unwrap();
        counter.count += 1;
        let count = counter.count;
        self.save_to_file(&counter)?;
        tracing::info!("Activity counter incremented to: {}", count);
        Ok(count)
    }

    /// Get current counter value
    pub fn get(&self) -> u64 {
        let counter = self.counter.lock().unwrap();
        counter.count
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_counter_increment() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("counter.json");

        let manager = ActivityCounterManager::new(&file_path).unwrap();
        assert_eq!(manager.get(), 0);

        assert_eq!(manager.increment().unwrap(), 1);
        assert_eq!(manager.get(), 1);

        assert_eq!(manager.increment().unwrap(), 2);
        assert_eq!(manager.get(), 2);
    }

    #[test]
    fn test_counter_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("counter.json");

        {
            let manager = ActivityCounterManager::new(&file_path).unwrap();
            manager.increment().unwrap();
            manager.increment().unwrap();
        }

        // Create new manager, should load from file
        let manager = ActivityCounterManager::new(&file_path).unwrap();
        assert_eq!(manager.get(), 2);
    }
}
