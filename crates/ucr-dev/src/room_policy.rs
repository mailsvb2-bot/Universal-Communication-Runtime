//! Local-room moderation that survives a process restart.
//!
//! Kick, block and a timed chat ban are room policy on top of the canonical
//! participant record. The block list is what stops a removed attendee from
//! being enrolled again. A chat ban expires on its own.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RoomPolicy {
    #[serde(default)]
    names: BTreeMap<String, String>,
    #[serde(default)]
    roles: BTreeMap<String, String>,
    #[serde(default)]
    devices: BTreeMap<String, String>,
    #[serde(default)]
    blocked: BTreeSet<String>,
    #[serde(default)]
    blocked_devices: BTreeSet<String>,
    #[serde(default)]
    silenced_until: BTreeMap<String, i64>,
}

impl RoomPolicy {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(format!("read room moderation policy: {error}")),
        };
        serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode room moderation policy: {error}"))
    }

    pub(crate) fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("room policy directory: {error}"))?;
        }
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| format!("encode room policy: {error}"))?;
        let temporary = path.with_extension("json.tmp");
        write_private(&temporary, &bytes)?;
        fs::rename(&temporary, path).map_err(|error| format!("store room policy: {error}"))?;
        Ok(())
    }

    pub(crate) fn remember(
        &mut self,
        external_user_id: &str,
        name: &str,
        role: &str,
        device: &str,
    ) {
        self.names
            .insert(external_user_id.to_owned(), name.to_owned());
        self.roles
            .insert(external_user_id.to_owned(), role.to_owned());
        if !device.is_empty() {
            self.devices
                .insert(external_user_id.to_owned(), device.to_owned());
        }
    }

    pub(crate) fn is_blocked(
        &self,
        external_user_id: Option<&str>,
        device_id: Option<&str>,
    ) -> bool {
        external_user_id.is_some_and(|value| self.blocked.contains(value))
            || device_id.is_some_and(|value| self.blocked_devices.contains(value))
    }

    pub(crate) fn silence_message(
        &self,
        external_user_id: &str,
        now_unix_ms: i64,
    ) -> Option<String> {
        let until = self.silenced_until.get(external_user_id).copied()?;
        if until <= now_unix_ms {
            return None;
        }
        Some(format!(
            "Спикер запретил вам писать в чат до {}.",
            format_clock(until)
        ))
    }

    pub(crate) fn block(&mut self, external_user_id: &str) {
        self.blocked.insert(external_user_id.to_owned());
        if let Some(device) = self.devices.get(external_user_id).cloned() {
            self.blocked_devices.insert(device);
        }
    }

    pub(crate) fn unblock(&mut self, external_user_id: &str) {
        self.blocked.remove(external_user_id);
        if let Some(device) = self.devices.get(external_user_id) {
            self.blocked_devices.remove(device);
        }
        self.silenced_until.remove(external_user_id);
    }

    pub(crate) fn silence(&mut self, external_user_id: &str, until_unix_ms: i64) {
        self.silenced_until
            .insert(external_user_id.to_owned(), until_unix_ms);
    }

    pub(crate) fn unsilence(&mut self, external_user_id: &str) {
        self.silenced_until.remove(external_user_id);
    }

    pub(crate) fn display_name<'a>(&'a self, external_user_id: &'a str) -> &'a str {
        self.names
            .get(external_user_id)
            .map_or(external_user_id, String::as_str)
    }

    pub(crate) fn role(&self, external_user_id: &str) -> Option<&str> {
        self.roles.get(external_user_id).map(String::as_str)
    }

    pub(crate) fn silenced_until(&self, external_user_id: &str) -> Option<i64> {
        self.silenced_until.get(external_user_id).copied()
    }

    pub(crate) fn blocked_ids(&self) -> impl Iterator<Item = &str> {
        self.blocked.iter().map(String::as_str)
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("write room policy: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("write room policy: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("write room policy: {error}"))?;
    Ok(())
}

fn format_clock(unix_ms: i64) -> String {
    let seconds = unix_ms.div_euclid(1000).rem_euclid(86_400);
    let hour = seconds.div_euclid(3600);
    let minute = seconds.rem_euclid(3600).div_euclid(60);
    format!("{hour:02}:{minute:02} UTC")
}

pub(crate) fn silence_deadline(now_unix_ms: i64, minutes: u32) -> Result<i64, String> {
    if !matches!(minutes, 5 | 15 | 60) {
        return Err("запрет чата можно поставить на 5, 15 или 60 минут".to_owned());
    }
    let delta = i64::from(minutes)
        .checked_mul(60_000)
        .ok_or_else(|| "clock overflow".to_owned())?;
    now_unix_ms
        .checked_add(delta)
        .ok_or_else(|| "clock overflow".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_and_silence_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "ucr-room-policy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = dir.join("moderation.json");
        let mut policy = RoomPolicy::default();
        policy.remember("user-aaaaaaaa", "Боря", "attendee", "device-1");
        policy.block("user-aaaaaaaa");
        policy.silence(
            "user-bbbbbbbb",
            silence_deadline(1_000, 15).expect("deadline"),
        );
        policy.save(&path).expect("save");
        let loaded = RoomPolicy::load(&path).expect("load");
        assert!(loaded.is_blocked(Some("user-aaaaaaaa"), None));
        assert!(loaded.is_blocked(None, Some("device-1")));
        assert!(loaded.silence_message("user-bbbbbbbb", 1_000).is_some());
        assert!(loaded.silence_message("user-bbbbbbbb", i64::MAX).is_none());
        let _ = fs::remove_dir_all(dir);
    }
    #[test]
    fn missing_policy_is_empty_but_corrupt_policy_fails_closed() {
        let dir = std::env::temp_dir().join(format!(
            "ucr-room-policy-invalid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("moderation.json");
        assert_eq!(
            RoomPolicy::load(&path).expect("new policy"),
            RoomPolicy::default()
        );
        fs::write(&path, b"{truncated").expect("corrupt policy");
        assert!(
            RoomPolicy::load(&path).is_err(),
            "corruption must not unblock users"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
