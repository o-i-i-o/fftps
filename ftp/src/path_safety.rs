//! FTP 虚拟路径净化与真实路径防逃逸（jail）
//!
//! 整合自 wftpd-windows 的 `core/path_utils.rs` + `core/path_resolve.rs`：
//! - 虚拟路径净化 [`normalize_virtual_path`]：统一 `/` 与 `\` 分隔符、折叠 `.`、
//!   处理 `..`（越界即报错，不再回退到根）、校验路径成分合法性、限制最大深度；
//! - 真实路径防逃逸 [`resolve_in_root`]：canonicalize 后检查仍在根目录之下，
//!   并按 [`allow_symlinks`](resolve_in_root) 策略拒绝符号链接逃逸。
//!
//! 与 `fftp-common` 的 `paths`（只做目录定位）互补：本模块只做净化与越界防护。
//!
//! 路径成分校验（非法字符、Windows 保留名）**全平台统一应用**，保证同一份
//! 配置与用例在 Linux / Windows 上行为一致，也避免共享目录同步到 Windows
//! 后出现不可见的非法文件名。

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// 虚拟路径最大深度（防止构造超深路径拖垮递归遍历）
pub const MAX_PATH_DEPTH: usize = 64;

/// 路径处理错误
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// 路径逃逸出根目录（`..` 越界或符号链接指向外部）
    PathEscape,
    /// 目标不是目录
    NotADirectory,
    /// 路径不存在
    NotFound,
    /// 路径深度超过 [`MAX_PATH_DEPTH`]
    PathTooDeep,
    /// 根目录不存在
    RootNotFound,
    /// canonicalize 失败
    CanonicalizeFailed,
    /// 路径包含非法成分
    InvalidPath,
    /// 命中不允许的符号链接
    SymlinkNotAllowed,
    /// 不在根目录之下
    PathNotUnderRoot,
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathError::PathEscape => write!(f, "检测到路径逃逸"),
            PathError::NotADirectory => write!(f, "目标不是目录"),
            PathError::NotFound => write!(f, "路径不存在"),
            PathError::PathTooDeep => write!(f, "路径深度超过上限"),
            PathError::RootNotFound => write!(f, "根目录不存在"),
            PathError::CanonicalizeFailed => write!(f, "路径规范化失败"),
            PathError::InvalidPath => write!(f, "路径包含非法成分"),
            PathError::SymlinkNotAllowed => write!(f, "不允许符号链接"),
            PathError::PathNotUnderRoot => write!(f, "不在根目录之下"),
        }
    }
}

impl std::error::Error for PathError {}

/// 路径前缀包含判断（Windows 不区分大小写）
pub fn path_starts_with_ignore_case<P: AsRef<Path>>(path: &Path, prefix: P) -> bool {
    #[cfg(windows)]
    {
        let path_str = path.to_string_lossy().to_lowercase();
        let prefix_str = prefix.as_ref().to_string_lossy().to_lowercase();
        path_str.starts_with(&prefix_str)
    }
    #[cfg(not(windows))]
    {
        path.starts_with(prefix.as_ref())
    }
}

/// 路径相等判断（Windows 不区分大小写）
pub fn paths_equal_ignore_case<P1: AsRef<Path>, P2: AsRef<Path>>(path1: P1, path2: P2) -> bool {
    #[cfg(windows)]
    {
        let s1 = path1.as_ref().to_string_lossy().to_lowercase();
        let s2 = path2.as_ref().to_string_lossy().to_lowercase();
        s1 == s2
    }
    #[cfg(not(windows))]
    {
        path1.as_ref() == path2.as_ref()
    }
}

/// 判断 FTP 路径是否为绝对路径（`/`、`\` 开头或平台绝对路径）
#[must_use]
pub fn is_absolute_ftp_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    if Path::new(path).is_absolute() {
        return true;
    }
    matches!(path.chars().next(), Some('/') | Some('\\'))
}

/// 校验单个路径成分是否合法（全平台统一严格规则）
///
/// - `.` 与 `..` 由 [`normalize_virtual_path`] 单独处理，这里视为合法；
/// - 拒绝空串/全空白、`:`（盘符/NTFS 数据流）、`<>:"|?*`、控制字符；
/// - 拒绝 Windows 保留设备名（CON/PRN/AUX/NUL/COM1-9/LPT1-9，含带扩展名形态）。
#[must_use]
pub fn is_valid_path_component(name: &OsStr) -> bool {
    let name_str = name.to_string_lossy();
    let name_str = name_str.trim();

    if name_str.is_empty() {
        return false;
    }

    if name_str == "." || name_str == ".." {
        return true;
    }

    if name_str.contains(':') {
        return false;
    }

    let invalid_chars = ['<', '>', '"', '|', '?', '*', '/', '\\'];
    if name_str.chars().any(|c| invalid_chars.contains(&c) || c.is_control()) {
        return false;
    }

    // Windows 保留设备名（含 `CON.txt` 这类带扩展名形态），全平台统一拒绝
    let stem = name_str.split('.').next().unwrap_or(name_str).to_uppercase();
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    !RESERVED.contains(&stem.as_str())
}

/// 把客户端送来的虚拟路径净化为 `/` 开头的规范形态
///
/// - `/` 与 `\` 均视为分隔符，输出统一用 `/`；
/// - 折叠 `.` 与重复分隔符；`..` 逐级回退，**越出根目录即报 [`PathError::PathEscape`]**
///   （不静默钳制，杜绝 `..` 探测）；
/// - 逐成分调用 [`is_valid_path_component`] 校验；
/// - 深度超过 [`MAX_PATH_DEPTH`] 报 [`PathError::PathTooDeep`]；
/// - 空路径 / `.` / `/` 均返回 `"/"`。
///
/// # Errors
/// 返回 [`PathError::InvalidPath`] / [`PathError::PathEscape`] / [`PathError::PathTooDeep`]
pub fn normalize_virtual_path(path: &str) -> Result<String, PathError> {
    let mut stack: Vec<&str> = Vec::new();

    for raw in path.split(['/', '\\']) {
        let name = raw.trim();
        match name {
            "" | "." => {}
            ".." => {
                if stack.pop().is_none() {
                    tracing::warn!(path, "虚拟路径通过 .. 越出根目录，已拒绝");
                    return Err(PathError::PathEscape);
                }
            }
            _ => {
                if !is_valid_path_component(OsStr::new(name)) {
                    tracing::warn!(path, component = name, "虚拟路径包含非法成分");
                    return Err(PathError::InvalidPath);
                }
                if stack.len() >= MAX_PATH_DEPTH {
                    tracing::warn!(path, depth = stack.len(), "虚拟路径深度超限");
                    return Err(PathError::PathTooDeep);
                }
                stack.push(name);
            }
        }
    }

    if stack.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(format!("/{}", stack.join("/")))
    }
}

/// 检查 `root` 之下已存在的路径成分是否含符号链接（不检查 root 自身的祖先链）
fn contains_symlink(root: &Path, resolved: &Path) -> bool {
    let Ok(relative) = resolved.strip_prefix(root) else {
        return false;
    };
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return true;
                }
            }
            // 后缀尚未创建，无从判断
            Err(_) => break,
        }
    }
    false
}

/// canonicalize 已存在路径并校验仍在根目录之下
fn canonicalize_and_validate(
    resolved: &Path,
    root_canon: &Path,
    allow_symlinks: bool,
) -> Result<PathBuf, PathError> {
    if !allow_symlinks && contains_symlink(root_canon, resolved) {
        tracing::warn!(path = %resolved.display(), "命中符号链接但当前配置不允许");
        return Err(PathError::SymlinkNotAllowed);
    }

    match resolved.canonicalize() {
        Ok(canon) => {
            if !path_starts_with_ignore_case(&canon, root_canon) {
                tracing::warn!(
                    path = %canon.display(),
                    root = %root_canon.display(),
                    "canonicalize 后越出根目录"
                );
                return Err(PathError::PathEscape);
            }
            Ok(canon)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // 目标（或中间段）不存在：校验最近存在的祖先目录仍在根之下
            let mut ancestor = resolved.to_path_buf();
            loop {
                if let Ok(canon) = ancestor.canonicalize() {
                    if !path_starts_with_ignore_case(&canon, root_canon) {
                        tracing::warn!(
                            path = %canon.display(),
                            root = %root_canon.display(),
                            "祖先目录越出根目录"
                        );
                        return Err(PathError::PathEscape);
                    }
                    return Ok(resolved.to_path_buf());
                }
                if !ancestor.pop() {
                    return Err(PathError::NotFound);
                }
            }
        }
        Err(_) => Err(PathError::CanonicalizeFailed),
    }
}

/// 把虚拟路径安全地解析为根目录 `root` 之下的真实路径
///
/// 流程：[`normalize_virtual_path`] → 拼接真实路径 → canonicalize 越界检查
/// （目标不存在时校验最近存在的祖先目录）→ 符号链接策略
/// （`allow_symlinks = false` 时拒绝路径中任何符号链接成分）。
///
/// # Errors
/// 净化失败返回对应 [`PathError`]；根目录不存在返回 [`PathError::RootNotFound`]；
/// 越界返回 [`PathError::PathEscape`]；符号链接策略拒绝返回 [`PathError::SymlinkNotAllowed`]
pub fn resolve_in_root(
    root: &Path,
    virtual_path: &str,
    allow_symlinks: bool,
) -> Result<PathBuf, PathError> {
    let root_canon = root
        .canonicalize()
        .map_err(|_| PathError::RootNotFound)?;

    let normalized = normalize_virtual_path(virtual_path)?;
    let resolved = join_virtual(&root_canon, &normalized);

    canonicalize_and_validate(&resolved, &root_canon, allow_symlinks)
}

/// 把 `/a/b` 形态的虚拟路径拼到 `base` 之下（保持平台原生分隔符，跳过 `.` 成分）
fn join_virtual(base: &Path, virtual_path: &str) -> PathBuf {
    let mut result = base.to_path_buf();
    for name in virtual_path.split('/').filter(|s| !s.is_empty() && *s != ".") {
        result.push(name);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_absolute_ftp_path() {
        assert!(is_absolute_ftp_path("/home/user"));
        assert!(is_absolute_ftp_path("\\home\\user"));
        assert!(is_absolute_ftp_path("/"));
        assert!(!is_absolute_ftp_path("relative/path"));
        assert!(!is_absolute_ftp_path(""));
    }

    #[test]
    fn test_is_valid_path_component() {
        assert!(is_valid_path_component(OsStr::new("valid_name")));
        assert!(is_valid_path_component(OsStr::new("..")));
        assert!(is_valid_path_component(OsStr::new(".")));
        assert!(!is_valid_path_component(OsStr::new("invalid:name")));
        assert!(!is_valid_path_component(OsStr::new("")));
    }

    #[test]
    fn test_is_valid_path_component_reserved() {
        // 保留名全平台统一拒绝（含带扩展名形态），非保留名放行
        assert!(!is_valid_path_component(OsStr::new("CON")));
        assert!(!is_valid_path_component(OsStr::new("PRN")));
        assert!(!is_valid_path_component(OsStr::new("AUX")));
        assert!(!is_valid_path_component(OsStr::new("NUL")));
        assert!(!is_valid_path_component(OsStr::new("COM1")));
        assert!(!is_valid_path_component(OsStr::new("LPT1")));
        assert!(!is_valid_path_component(OsStr::new("con.txt")));
        assert!(is_valid_path_component(OsStr::new("con1")));
    }

    #[test]
    fn test_is_valid_path_component_invalid_chars() {
        assert!(!is_valid_path_component(OsStr::new("file<name")));
        assert!(!is_valid_path_component(OsStr::new("file>name")));
        assert!(!is_valid_path_component(OsStr::new("file\"name")));
        assert!(!is_valid_path_component(OsStr::new("file|name")));
        assert!(!is_valid_path_component(OsStr::new("file?name")));
        assert!(!is_valid_path_component(OsStr::new("file*name")));
    }

    #[test]
    fn test_is_valid_path_component_empty() {
        assert!(!is_valid_path_component(OsStr::new("")));
        assert!(!is_valid_path_component(OsStr::new("  ")));
    }

    #[test]
    fn test_normalize_virtual_path() {
        assert_eq!(normalize_virtual_path("/").unwrap(), "/");
        assert_eq!(normalize_virtual_path("").unwrap(), "/");
        assert_eq!(normalize_virtual_path(".").unwrap(), "/");
        assert_eq!(normalize_virtual_path("/a/b").unwrap(), "/a/b");
        assert_eq!(normalize_virtual_path("a/b").unwrap(), "/a/b");
        assert_eq!(normalize_virtual_path("/a/./b").unwrap(), "/a/b");
        assert_eq!(normalize_virtual_path("/a/c/../b").unwrap(), "/a/b");
        assert_eq!(normalize_virtual_path("/a//b").unwrap(), "/a/b");
        assert_eq!(normalize_virtual_path("\\a\\b").unwrap(), "/a/b");
    }

    #[test]
    fn test_normalize_virtual_path_escape() {
        assert_eq!(normalize_virtual_path("/..").unwrap_err(), PathError::PathEscape);
        assert_eq!(
            normalize_virtual_path("/a/../../b").unwrap_err(),
            PathError::PathEscape
        );
        assert_eq!(normalize_virtual_path("../x").unwrap_err(), PathError::PathEscape);
    }

    #[test]
    fn test_normalize_virtual_path_invalid() {
        assert_eq!(
            normalize_virtual_path("/a/b:c").unwrap_err(),
            PathError::InvalidPath
        );
        assert_eq!(
            normalize_virtual_path("/CON/x").unwrap_err(),
            PathError::InvalidPath
        );
    }

    #[test]
    fn test_normalize_virtual_path_too_deep() {
        let deep = format!("/{}", (0..=MAX_PATH_DEPTH).map(|_| "a").collect::<Vec<_>>().join("/"));
        assert_eq!(normalize_virtual_path(&deep).unwrap_err(), PathError::PathTooDeep);
    }

    #[test]
    fn test_path_error_display() {
        assert_eq!(PathError::PathEscape.to_string(), "检测到路径逃逸");
        assert_eq!(PathError::NotADirectory.to_string(), "目标不是目录");
        assert_eq!(PathError::NotFound.to_string(), "路径不存在");
        assert_eq!(PathError::PathTooDeep.to_string(), "路径深度超过上限");
        assert_eq!(PathError::RootNotFound.to_string(), "根目录不存在");
        assert_eq!(PathError::CanonicalizeFailed.to_string(), "路径规范化失败");
        assert_eq!(PathError::InvalidPath.to_string(), "路径包含非法成分");
        assert_eq!(PathError::SymlinkNotAllowed.to_string(), "不允许符号链接");
        assert_eq!(PathError::PathNotUnderRoot.to_string(), "不在根目录之下");
    }

    #[test]
    fn test_resolve_in_root_normal() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("sub")).unwrap();
        std::fs::write(root.path().join("sub/file.txt"), b"x").unwrap();

        let resolved = resolve_in_root(root.path(), "/sub/file.txt", false).unwrap();
        assert!(paths_equal_ignore_case(
            resolved,
            root.path().join("sub").join("file.txt").canonicalize().unwrap()
        ));

        // 根目录自身
        let root_resolved = resolve_in_root(root.path(), "/", false).unwrap();
        assert!(paths_equal_ignore_case(
            root_resolved,
            root.path().canonicalize().unwrap()
        ));

        // 尚不存在的文件：校验祖先目录后返回拼接路径
        let missing = resolve_in_root(root.path(), "/sub/new.txt", false).unwrap();
        assert!(missing.ends_with("sub/new.txt") || missing.ends_with(r"sub\new.txt"));
    }

    #[test]
    fn test_resolve_in_root_escape() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_in_root(root.path(), "/../etc", false).unwrap_err(),
            PathError::PathEscape
        );
        assert_eq!(
            resolve_in_root(root.path(), "/no-such-root", false).is_ok(),
            true
        );
    }

    #[test]
    fn test_resolve_in_root_root_not_found() {
        assert_eq!(
            resolve_in_root(Path::new("/no-such-dir-fftp-12345"), "/a", false).unwrap_err(),
            PathError::RootNotFound
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_resolve_in_root_symlink_policy() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();

        // 拒绝符号链接
        assert_eq!(
            resolve_in_root(root.path(), "/link/secret.txt", false).unwrap_err(),
            PathError::SymlinkNotAllowed
        );

        // 允许符号链接但目标在根外 → 越界
        assert_eq!(
            resolve_in_root(root.path(), "/link/secret.txt", true).unwrap_err(),
            PathError::PathEscape
        );

        // 允许符号链接且目标在根内 → 通过
        std::os::unix::fs::symlink(root.path().join("sub"), root.path().join("inner")).unwrap();
        std::fs::create_dir(root.path().join("sub")).unwrap();
        assert!(resolve_in_root(root.path(), "/inner", true).is_ok());
    }
}
