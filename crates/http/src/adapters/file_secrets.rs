//! Explicit references to operator-mounted Secret files. No database writes,
//! plaintext cache, or implicit interpretation of caller-supplied paths.

use crate::ports::{SecretResolver, StoreError};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const MAX_SECRET_BYTES: usize = 65_536;
const MAX_BINDINGS: usize = 256;

/// A dedicated read-only mount and an explicit reference → Secret key mapping.
/// Clones share the root descriptor and concurrency limit, but never cache
/// plaintext. Kubernetes `..data` symlinks may target generations inside this
/// root; descriptors confine the final read even if a path changes meanwhile.
#[derive(Clone)]
pub struct FileSecretResolver {
    mount: Arc<Mount>,
    slots: Arc<Semaphore>,
}

struct Mount {
    root: PathBuf,
    directory: File,
    bindings: BTreeMap<String, String>,
}

fn invalid() -> StoreError {
    StoreError::Permanent("Mounted secret configuration invalid".into())
}

fn unavailable() -> StoreError {
    StoreError::Transient("Mounted secret read unavailable".into())
}

fn directory_valid(file: &File) -> Result<(), StoreError> {
    let metadata = file.metadata().map_err(|_| unavailable())?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(invalid());
    }
    Ok(())
}

fn open_at(directory: &File, name: &Path, flags: i32) -> Result<File, StoreError> {
    let name = CString::new(name.as_os_str().as_bytes()).map_err(|_| invalid())?;
    // SAFETY: directory is live for this call and name is a terminated string.
    // O_CREAT is absent; a successful descriptor is immediately owned by File.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | flags,
        )
    };
    if descriptor < 0 {
        return Err(match io::Error::last_os_error().raw_os_error() {
            Some(libc::ELOOP | libc::ENOTDIR | libc::EACCES | libc::EPERM) => invalid(),
            _ => unavailable(),
        });
    }
    // SAFETY: openat returned a new descriptor; no other owner exists.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

impl FileSecretResolver {
    #[cfg(feature = "postgres")]
    pub(crate) fn has_reference(&self, reference: &str) -> bool {
        self.mount.bindings.contains_key(reference)
    }

    /// Bind logical references to flat Secret keys before serving traffic.
    /// An empty map explicitly disables reference resolution. Private signing
    /// and encryption mounts must be configured separately from this root.
    pub fn new(
        root: impl AsRef<Path>,
        bindings: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, StoreError> {
        let root = root.as_ref().canonicalize().map_err(|_| invalid())?;
        let before = root.metadata().map_err(|_| invalid())?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&root)
            .map_err(|_| invalid())?;
        directory_valid(&directory)?;
        let opened = directory.metadata().map_err(|_| invalid())?;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(invalid());
        }
        let mut configured = BTreeMap::new();
        for (reference, name) in bindings {
            if reference.is_empty()
                || reference.len() > 1024
                || reference
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control())
                || name.is_empty()
                || name.len() > 253
                || name.starts_with("..")
                || name == "."
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                || configured.insert(reference, name).is_some()
                || configured.len() > MAX_BINDINGS
            {
                return Err(invalid());
            }
        }
        Ok(Self {
            mount: Arc::new(Mount {
                root,
                directory,
                bindings: configured,
            }),
            slots: Arc::new(Semaphore::new(16)),
        })
    }
}

impl Mount {
    fn read(&self, name: &str) -> Result<Option<String>, StoreError> {
        directory_valid(&self.directory)?;
        let root_metadata = self.root.metadata().map_err(|_| unavailable())?;
        let opened_root = self.directory.metadata().map_err(|_| unavailable())?;
        if root_metadata.dev() != opened_root.dev() || root_metadata.ino() != opened_root.ino() {
            return Err(invalid());
        }
        let path = match self.root.join(name).canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(invalid()),
        };
        let relative = path.strip_prefix(&self.root).map_err(|_| invalid())?;
        let before = path.metadata().map_err(|_| unavailable())?;
        if !before.is_file() || before.len() > MAX_SECRET_BYTES as u64 {
            return Err(invalid());
        }
        let mut components = relative.components().peekable();
        let mut directory = self.directory.try_clone().map_err(|_| unavailable())?;
        let file = loop {
            let Component::Normal(component) = components.next().ok_or_else(invalid)? else {
                return Err(invalid());
            };
            if components.peek().is_none() {
                break open_at(&directory, Path::new(component), 0)?;
            }
            directory = open_at(&directory, Path::new(component), libc::O_DIRECTORY)?;
            directory_valid(&directory)?;
        };
        let opened = file.metadata().map_err(|_| unavailable())?;
        if !opened.is_file()
            || opened.len() > MAX_SECRET_BYTES as u64
            || opened.permissions().mode() & 0o137 != 0
            || before.dev() != opened.dev()
            || before.ino() != opened.ino()
        {
            return Err(invalid());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take((MAX_SECRET_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| unavailable())?;
        if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES || bytes.contains(&0) {
            return Err(invalid());
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
        Ok(Some(text.to_owned()))
    }
}

impl SecretResolver for FileSecretResolver {
    async fn resolve(&self, secret_ref: &str) -> Result<Option<String>, StoreError> {
        let Some(name) = self.mount.bindings.get(secret_ref).cloned() else {
            return Ok(None);
        };
        let slot = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| unavailable())?;
        let mount = self.mount.clone();
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            mount.read(&name)
        })
        .await
        .map_err(|_| unavailable())?
    }
}
