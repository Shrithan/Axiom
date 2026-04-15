use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

pub fn supported(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    !name.starts_with('.')
        && !name.to_lowercase().contains(".protected.")
        && matches!(
            path.extension()
                .and_then(|s| s.to_str())
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("pdf" | "docx" | "xlsx" | "txt" | "csv")
        )
}
pub fn resolve(path: &Path, folders: &[String]) -> Result<(PathBuf, Vec<u8>), String> {
    if !supported(path) {
        return Err("Unsupported or ignored file".into());
    }
    if std::fs::symlink_metadata(path)
        .map_err(|_| "File unavailable")?
        .file_type()
        .is_symlink()
    {
        return Err("Symbolic links are not scanned".into());
    }
    let canonical = path.canonicalize().map_err(|_| "File unavailable")?;
    let allowed = folders
        .iter()
        .filter_map(|p| Path::new(p).canonicalize().ok())
        .any(|root| canonical.starts_with(root));
    if !allowed {
        return Err("File is outside configured folders".into());
    }
    let file = open_confined(&canonical)?;
    let before = file.metadata().map_err(|_| "File unavailable")?;
    if !before.is_file() || before.len() == 0 || before.len() > 20 * 1024 * 1024 {
        return Err("File is empty or exceeds 20 MiB".into());
    }
    let mut bytes = Vec::new();
    let mut reader = file.take(20 * 1024 * 1024 + 1);
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| "File read failed")?;
    let after = reader
        .get_ref()
        .metadata()
        .map_err(|_| "File unavailable")?;
    if bytes.len() > 20 * 1024 * 1024
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err("File changed during reading; next save will be scanned".into());
    }
    Ok((canonical, bytes))
}
// Walk directory descriptors without following symlinks, including ancestors.
// This closes the canonicalize/open race if a directory is replaced by a link.
#[cfg(unix)]
fn open_confined(path: &Path) -> Result<std::fs::File, String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut directory = options
        .open("/")
        .map_err(|_| "File directory unavailable")?;
    let parts: Vec<_> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(p) => Some(p),
            _ => None,
        })
        .collect();
    for (index, part) in parts.iter().enumerate() {
        let name = std::ffi::CString::new(part.as_bytes()).map_err(|_| "Invalid file path")?;
        let last = index + 1 == parts.len();
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if last {
                libc::O_NONBLOCK
            } else {
                libc::O_DIRECTORY
            };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err("File unavailable or path changed; select the folder again".into());
        }
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        if last {
            return Ok(file);
        }
        directory = file;
    }
    Err("Invalid file path".into())
}
#[cfg(not(unix))]
fn open_confined(path: &Path) -> Result<std::fs::File, String> {
    std::fs::File::open(path).map_err(|_| "File unavailable".into())
}

#[derive(Default)]
pub struct Fingerprints(HashMap<PathBuf, ([u8; 32], u64)>);
impl Fingerprints {
    pub fn unchanged(&mut self, path: PathBuf, data: &[u8], revision: u64) -> bool {
        let hash: [u8; 32] = Sha256::digest(data).into();
        let same = self.0.get(&path) == Some(&(hash, revision));
        if self.0.len() >= 1024 && !self.0.contains_key(&path) {
            self.0.clear();
        }
        self.0.insert(path, (hash, revision));
        same
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats_and_ignores() {
        for p in ["a.txt", "a.CSV", "a.pdf", "a.docx", "a.xlsx"] {
            assert!(supported(Path::new(p)));
        }
        for p in ["a.exe", "a.xlsm", ".lock.txt", "a.protected.txt"] {
            assert!(!supported(Path::new(p)));
        }
    }
    #[test]
    fn hash_suppresses_identical_content() {
        let mut f = Fingerprints::default();
        assert!(!f.unchanged("a".into(), b"content", 0));
        assert!(f.unchanged("a".into(), b"content", 0));
        assert!(!f.unchanged("a".into(), b"changed", 0));
    }
    #[test]
    fn policy_revision_invalidates_hash() {
        let mut f = Fingerprints::default();
        f.unchanged("a".into(), b"content", 0);
        assert!(!f.unchanged("a".into(), b"content", 1));
    }
    #[test]
    fn path_escape_rejected() {
        let root = std::env::temp_dir().join(format!("axiom-path-test-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("a.txt");
        std::fs::write(&file, b"test").unwrap();
        assert!(resolve(&file, &[root.to_string_lossy().into()]).is_ok());
        assert!(resolve(&file, &[root.join("other").to_string_lossy().into()]).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn symlink_rejected() {
        let root = std::env::temp_dir().join(format!("axiom-link-test-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"test").unwrap();
        std::os::unix::fs::symlink(root.join("a.txt"), root.join("link.txt")).unwrap();
        assert!(resolve(&root.join("link.txt"), &[root.to_string_lossy().into()]).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
