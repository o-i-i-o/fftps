//! 路径净化与 jail 解析层
//!
//! 迁移自 wftpd-windows `core/path_utils.rs` + `core/path_resolve.rs`：
//! 逻辑 chroot（把客户端路径锚定到用户 home）、词法归一化、符号链接链校验、
//! 目录深度限制与 Windows 保留名/非法字符拦截。Linux/Windows 双平台正确
//! （大小写敏感性与非法字符规则按平台 `cfg` 分化）。

use std::path::{Component, Path, PathBuf};

/// 相对 home 的最大目录深度，超过视为攻击
pub const MAX_PATH_DEPTH: usize = 64;

/// 路径解析失败原因
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathResolveError {
    /// 尝试逃逸 home 目录
    PathEscape,
    /// 目标不是目录
    NotADirectory,
    /// 目标不存在
    NotFound,
    /// 目录层级过深
    PathTooDeep,
    /// home 目录不可用
    HomeDirectoryNotFound,
    /// 规范化失败
    CanonicalizeFailed,
    /// 路径包含非法成分
    InvalidPath,
    /// 不允许符号链接
    SymlinkNotAllowed,
    /// 路径不在 home 之下
    PathNotUnderHome,
}

impl std::fmt::Display for PathResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathEscape => write!(f, "Path escape detected"),
            Self::NotADirectory => write!(f, "Path is not a directory"),
            Self::NotFound => write!(f, "Path not found"),
            Self::PathTooDeep => write!(f, "Path depth exceeds maximum limit"),
            Self::HomeDirectoryNotFound => write!(f, "Home directory not found"),
            Self::CanonicalizeFailed => write!(f, "Path canonicalization failed"),
            Self::InvalidPath => write!(f, "Invalid path"),
            Self::SymlinkNotAllowed => write!(f, "Symlinks not allowed"),
            Self::PathNotUnderHome => write!(f, "Path not under home directory"),
        }
    }
}

impl std::error::Error for PathResolveError {}

/// 去掉 Windows 扩展长度前缀 `\\?\`（canonicalize 的产物）
#[must_use]
pub fn strip_extended_prefix(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    let stripped = path_str.strip_prefix(r"\\?\").unwrap_or(&path_str);
    PathBuf::from(stripped)
}

/// 路径前缀包含判断：Windows 忽略大小写，Unix 严格比较
#[must_use]
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

/// 路径相等判断：Windows 忽略大小写，Unix 严格比较
#[must_use]
pub fn paths_equal_ignore_case<P1: AsRef<Path>, P2: AsRef<Path>>(path1: P1, path2: P2) -> bool {
    #[cfg(windows)]
    {
        let str1 = path1.as_ref().to_string_lossy().to_lowercase();
        let str2 = path2.as_ref().to_string_lossy().to_lowercase();
        str1 == str2
    }
    #[cfg(not(windows))]
    {
        path1.as_ref() == path2.as_ref()
    }
}

/// 服务器绝对路径 → 客户端虚路径（`/` 起的相对 home 路径）
///
/// # Errors
/// 路径不在 `home_dir` 之下时返回 [`PathResolveError::PathNotUnderHome`]
pub fn to_ftp_path(path: &Path, home_dir: &Path) -> Result<String, PathResolveError> {
    let normalized_path = strip_extended_prefix(path);
    let normalized_home = strip_extended_prefix(home_dir);

    let Ok(relative) = normalized_path.strip_prefix(&normalized_home) else {
        tracing::warn!(
            "to_ftp_path: path {:?} is not under home_dir {:?}",
            path,
            home_dir
        );
        return Err(PathResolveError::PathNotUnderHome);
    };
    let path_str = relative.to_string_lossy();
    let normalized = path_str.replace('\\', "/");
    if normalized.is_empty() || normalized == "." {
        Ok("/".to_string())
    } else {
        Ok(format!("/{}", normalized.trim_start_matches('/')))
    }
}

/// 是否客户端绝对虚路径（`/` 或 `\` 开头，或带盘符前缀）
#[must_use]
pub fn is_absolute_ftp_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    if Path::new(path).is_absolute() {
        return true;
    }
    matches!(path.chars().next(), Some('/' | '\\'))
}

/// 单个路径成分合法性：
/// `.`/`..` 放行（由后续归一化处理）；Windows 额外拦截盘符冒号、
/// 非法字符与设备保留名。
#[must_use]
pub fn is_valid_path_component(name: &std::ffi::OsStr) -> bool {
    let name_str = name.to_string_lossy();
    let name_str = name_str.trim();

    if name_str.is_empty() {
        return false;
    }

    if name_str == "." || name_str == ".." {
        return true;
    }

    #[cfg(windows)]
    {
        if name_str.contains(':') {
            return false;
        }

        let invalid_chars = ['<', '>', '"', '|', '?', '*'];
        if name_str.chars().any(|c| invalid_chars.contains(&c)) {
            return false;
        }

        let reserved_names = [
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];
        let upper = name_str.to_uppercase();
        if reserved_names.contains(&upper.as_str()) {
            return false;
        }
    }

    true
}

/// 词法解析：把客户端路径（绝对/相对）锚定到 `home_canon` 下，逐成分合法性检查
///
/// # Errors
/// 含非法成分、盘符前缀，或越出 home 时返回对应错误
pub fn resolve_path_internal(
    cwd: &str,
    home_canon: &Path,
    path: &str,
) -> Result<PathBuf, PathResolveError> {
    let clean_path = path.trim();

    if clean_path.is_empty() || clean_path == "." || clean_path == "./" {
        return Ok(home_canon.to_path_buf());
    }

    if clean_path.starts_with(r"\\?\") {
        let path_buf = PathBuf::from(clean_path);
        if !path_starts_with_ignore_case(&path_buf, home_canon) {
            tracing::warn!(
                "resolve_path_internal: extended path outside home - input: {:?}",
                clean_path
            );
            return Err(PathResolveError::PathEscape);
        }
        return Ok(path_buf);
    }

    if is_absolute_ftp_path(clean_path) {
        let relative = clean_path.trim_start_matches('/').trim_start_matches('\\');
        if relative.is_empty() {
            return Ok(home_canon.to_path_buf());
        }

        let relative_path = Path::new(relative);
        for component in relative_path.components() {
            if matches!(component, Component::Prefix(_) | Component::RootDir) {
                tracing::warn!(
                    "resolve_path_internal: invalid prefix/root in absolute path - input: {:?}",
                    clean_path
                );
                return Err(PathResolveError::InvalidPath);
            }
            if let Component::Normal(name) = component
                && !is_valid_path_component(name)
            {
                tracing::warn!(
                    "resolve_path_internal: invalid component {:?} in path {:?}",
                    name,
                    clean_path
                );
                return Err(PathResolveError::InvalidPath);
            }
        }

        let resolved_path = home_canon.join(relative);

        if !path_starts_with_ignore_case(&resolved_path, home_canon) {
            tracing::warn!(
                "resolve_path_internal: absolute path outside home - resolved: {:?}, input: {:?}",
                resolved_path,
                clean_path
            );
            return Err(PathResolveError::PathEscape);
        }

        Ok(resolved_path)
    } else {
        for component in Path::new(clean_path).components() {
            if matches!(component, Component::Prefix(_) | Component::RootDir) {
                tracing::warn!(
                    "resolve_path_internal: invalid prefix/root in relative path - input: {:?}",
                    clean_path
                );
                return Err(PathResolveError::InvalidPath);
            }
            if let Component::Normal(name) = component
                && !is_valid_path_component(name)
            {
                tracing::warn!(
                    "resolve_path_internal: invalid component {:?} in path {:?}",
                    name,
                    clean_path
                );
                return Err(PathResolveError::InvalidPath);
            }
        }

        let base = if cwd.is_empty() {
            home_canon.to_path_buf()
        } else {
            let cwd_path = PathBuf::from(cwd);
            if !path_starts_with_ignore_case(&cwd_path, home_canon) {
                tracing::warn!(
                    "resolve_path_internal: cwd outside home - cwd: {:?}, home: {:?}",
                    cwd,
                    home_canon
                );
                return Err(PathResolveError::PathEscape);
            }
            cwd_path
        };

        Ok(base.join(clean_path))
    }
}

/// 从 home 起逐成分重建路径，拦截 `..` 逃逸与超深路径
///
/// # Errors
/// `..` 逃出 home、成分非法或深度超限时返回对应错误
pub fn build_safe_path(
    home_canon: &Path,
    resolved: &Path,
    input_desc: &str,
) -> Result<PathBuf, PathResolveError> {
    let mut safe_path = home_canon.to_path_buf();
    let home_components: Vec<_> = home_canon.components().collect();
    let resolved_components: Vec<_> = resolved.components().collect();

    let mut relative_depth: usize = 0;

    for (i, component) in resolved_components.iter().enumerate() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if safe_path == *home_canon {
                    tracing::warn!(
                        "SECURITY: path escape via parent dir at root - input: {:?}",
                        input_desc
                    );
                    return Err(PathResolveError::PathEscape);
                }

                if !safe_path.pop() {
                    tracing::warn!("SECURITY: failed to pop path - input: {:?}", input_desc);
                    return Err(PathResolveError::PathEscape);
                }

                if !path_starts_with_ignore_case(&safe_path, home_canon) {
                    tracing::warn!(
                        "SECURITY: path escape after pop - safe_path: {:?}, input: {:?}",
                        safe_path,
                        input_desc
                    );
                    return Err(PathResolveError::PathEscape);
                }

                relative_depth = relative_depth.saturating_sub(1);
            }
            Component::Normal(name) => {
                if i < home_components.len() {
                    continue;
                }

                if !is_valid_path_component(name) {
                    tracing::warn!(
                        "build_safe_path: invalid component {:?} - input: {:?}",
                        name,
                        input_desc
                    );
                    return Err(PathResolveError::InvalidPath);
                }

                safe_path.push(name);
                relative_depth += 1;

                if relative_depth > MAX_PATH_DEPTH {
                    tracing::warn!(
                        "SECURITY: path depth exceeded - depth: {}, input: {:?}",
                        relative_depth,
                        input_desc
                    );
                    return Err(PathResolveError::PathTooDeep);
                }
            }
        }
    }

    if !path_starts_with_ignore_case(&safe_path, home_canon) {
        tracing::warn!(
            "SECURITY: final path outside home - safe_path: {:?}, input: {:?}",
            safe_path,
            input_desc
        );
        return Err(PathResolveError::PathEscape);
    }

    Ok(safe_path)
}

/// 规范化并校验已存在路径：canonicalize 后必须在 home 内，
/// `allow_symlink=false` 时逐成分拒绝符号链接。
///
/// # Errors
/// 越狱、含符号链接或规范化失败时返回对应错误
pub fn canonicalize_and_validate(
    path: &Path,
    home_canon: &Path,
    input_desc: &str,
    allow_symlink: bool,
) -> Result<PathBuf, PathResolveError> {
    match path.canonicalize() {
        Ok(canon) => {
            if !path_starts_with_ignore_case(&canon, home_canon) {
                tracing::warn!(
                    "SECURITY: path escape detected - canonicalized: {:?}, home: {:?}, input: {:?}",
                    canon,
                    home_canon,
                    input_desc
                );
                return Err(PathResolveError::PathEscape);
            }

            if !allow_symlink {
                if let Ok(metadata) = path.symlink_metadata()
                    && metadata.file_type().is_symlink()
                {
                    tracing::warn!(
                        "SECURITY: symlink not allowed - path: {:?}, input: {:?}",
                        path,
                        input_desc
                    );
                    return Err(PathResolveError::SymlinkNotAllowed);
                }

                check_path_components_for_symlinks(path, home_canon, input_desc)?;
            }

            Ok(canon)
        }
        Err(e) => {
            tracing::debug!(
                "canonicalize_and_validate: failed for {:?}: {} - input: {:?}",
                path,
                e,
                input_desc
            );
            Err(PathResolveError::CanonicalizeFailed)
        }
    }
}

/// 逐成分检查符号链接与越界
///
/// 只检查 home 之下的成分：`home_canon` 自身已完全规范化，其祖先目录
/// 属于 home 规范路径的一部分，不做越界判定（否则 `/tmp` 这类祖先目录
/// 必然不满足 `starts_with(home)` 而被误判为逃逸）。
///
/// # Errors
/// 成分为符号链接或越出 home 时返回对应错误
pub fn check_path_components_for_symlinks(
    path: &Path,
    home_canon: &Path,
    input_desc: &str,
) -> Result<(), PathResolveError> {
    let relative = path.strip_prefix(home_canon).map_err(|_| {
        tracing::warn!(
            "SECURITY: path not under home - {:?}, home: {:?}, input: {:?}",
            path,
            home_canon,
            input_desc
        );
        PathResolveError::PathEscape
    })?;

    let mut current = home_canon.to_path_buf();
    for component in relative.components() {
        match component {
            Component::Prefix(prefix) => {
                current.push(prefix.as_os_str());
            }
            Component::RootDir => {
                current.push(component);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if current == *home_canon {
                    tracing::warn!(
                        "SECURITY: parent dir escapes home - {:?}, input: {:?}",
                        path,
                        input_desc
                    );
                    return Err(PathResolveError::PathEscape);
                }
                current.pop();
            }
            Component::Normal(name) => {
                current.push(name);

                if let Ok(metadata) = current.symlink_metadata()
                    && metadata.file_type().is_symlink()
                {
                    tracing::warn!(
                        "SECURITY: symlink component detected - {:?} in {:?}",
                        current,
                        input_desc
                    );
                    return Err(PathResolveError::SymlinkNotAllowed);
                }

                if !path_starts_with_ignore_case(&current, home_canon) {
                    tracing::warn!(
                        "SECURITY: path component outside home - {:?}, input: {:?}",
                        current,
                        input_desc
                    );
                    return Err(PathResolveError::PathEscape);
                }
            }
        }
    }
    Ok(())
}

/// 允许符号链接时的链式校验：每个链接目标解析后必须仍落在 home 内
///
/// # Errors
/// 链上任一链接指向 home 之外（或不可解析）时返回对应错误
pub fn validate_symlink_chain(
    path: &Path,
    home_canon: &Path,
    input_desc: &str,
) -> Result<PathBuf, PathResolveError> {
    // 同 check_path_components_for_symlinks：从 home 边界起逐成分校验，
    // home 的祖先目录不参与链校验
    let relative = path.strip_prefix(home_canon).map_err(|_| {
        tracing::warn!(
            "validate_symlink_chain: path not under home - {:?}, home: {:?}, input: {:?}",
            path,
            home_canon,
            input_desc
        );
        PathResolveError::PathEscape
    })?;

    let mut current = home_canon.to_path_buf();
    let mut components = relative.components().peekable();

    while let Some(component) = components.next() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                current.push(component);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if current == *home_canon {
                    tracing::warn!(
                        "validate_symlink_chain: parent dir escapes home - {:?}, input: {:?}",
                        path,
                        input_desc
                    );
                    return Err(PathResolveError::PathEscape);
                }
                current.pop();
            }
            Component::Normal(name) => {
                current.push(name);

                if let Ok(metadata) = current.symlink_metadata()
                    && metadata.file_type().is_symlink()
                {
                    let link_target = std::fs::read_link(&current).map_err(|e| {
                        tracing::warn!(
                            "validate_symlink_chain: cannot read symlink {:?}: {} - input: {:?}",
                            current,
                            e,
                            input_desc
                        );
                        PathResolveError::SymlinkNotAllowed
                    })?;

                    let resolved_target = if link_target.is_absolute() {
                        link_target.clone()
                    } else {
                        let parent = current.parent().unwrap_or(Path::new("/"));
                        parent.join(&link_target)
                    };

                    // 目标已存在则取其规范路径；悬空链接用词法规整路径兜底
                    let canon_target = if let Ok(canon) = resolved_target.canonicalize() {
                        canon
                    } else {
                        let parent = current.parent().unwrap_or(Path::new("/"));
                        build_safe_path(home_canon, &parent.join(&link_target), input_desc)?
                    };

                    if !path_starts_with_ignore_case(&canon_target, home_canon) {
                        tracing::warn!(
                            "validate_symlink_chain: symlink target outside home - {:?} -> {:?}, input: {:?}",
                            current,
                            canon_target,
                            input_desc
                        );
                        return Err(PathResolveError::SymlinkNotAllowed);
                    }

                    if components.peek().is_some() {
                        current = canon_target;
                    }
                }
            }
        }
    }

    let final_path = path.canonicalize().unwrap_or(current);

    if !path_starts_with_ignore_case(&final_path, home_canon) {
        tracing::warn!(
            "validate_symlink_chain: final path outside home - {:?}, input: {:?}",
            final_path,
            input_desc
        );
        return Err(PathResolveError::PathEscape);
    }

    Ok(final_path)
}

/// 目标不存在时的兜底：校验父目录存在且未越界，返回拼接后的新路径
///
/// # Errors
/// 父目录越界/是符号链接/无法定位文件名时返回对应错误
pub fn validate_parent_and_build_path(
    path: &Path,
    home_canon: &Path,
    input_desc: &str,
) -> Result<PathBuf, PathResolveError> {
    let parent = path.parent().ok_or_else(|| {
        tracing::warn!("validate_parent: path has no parent - {:?}", input_desc);
        PathResolveError::InvalidPath
    })?;

    if paths_equal_ignore_case(parent, home_canon) {
        if !path_starts_with_ignore_case(path, home_canon) {
            tracing::warn!(
                "SECURITY: path outside home - path: {:?}, input: {:?}",
                path,
                input_desc
            );
            return Err(PathResolveError::PathEscape);
        }
        return Ok(path.to_path_buf());
    }

    let Ok(canon_parent) = parent.canonicalize() else {
        tracing::warn!(
            "validate_parent: parent does not exist - parent: {:?}, input: {:?}",
            parent,
            input_desc
        );
        return Err(PathResolveError::NotFound);
    };

    if !path_starts_with_ignore_case(&canon_parent, home_canon) {
        tracing::warn!(
            "SECURITY: parent directory outside home - parent: {:?}, input: {:?}",
            canon_parent,
            input_desc
        );
        return Err(PathResolveError::PathEscape);
    }

    if let Ok(metadata) = parent.symlink_metadata()
        && metadata.file_type().is_symlink()
    {
        tracing::warn!(
            "validate_parent: parent is symlink - parent: {:?}, input: {:?}",
            parent,
            input_desc
        );
        return Err(PathResolveError::SymlinkNotAllowed);
    }

    let file_name = path.file_name().ok_or_else(|| {
        tracing::warn!("validate_parent: path has no file name - {:?}", input_desc);
        PathResolveError::InvalidPath
    })?;

    let final_path = canon_parent.join(file_name);

    if !path_starts_with_ignore_case(&final_path, home_canon) {
        tracing::warn!(
            "SECURITY: final path outside home - final: {:?}, input: {:?}",
            final_path,
            input_desc
        );
        return Err(PathResolveError::PathEscape);
    }

    Ok(final_path)
}

/// SFTP 会话路径解析入口：客户端路径 → home 内服务器绝对路径（jail）。
///
/// 1. 词法解析锚定到 home（`..` 归一化、非法成分拦截）；
/// 2. 已存在路径 canonicalize + 越界/符号链接校验；
/// 3. 不存在路径回退父目录校验（新建文件/目录场景）。
///
/// # Errors
/// 任何越狱、非法路径或 home 不可用都会返回 [`PathResolveError`]
pub fn safe_resolve_path(
    cwd: &str,
    home_dir: &str,
    path: &str,
    allow_symlinks: bool,
) -> Result<PathBuf, PathResolveError> {
    let input_desc = format!("cwd={cwd}, home={home_dir}, path={path}");

    let home = PathBuf::from(home_dir);
    let home_canon = home.canonicalize().map_err(|e| {
        tracing::error!(
            "safe_resolve_path: cannot canonicalize home {:?}: {}",
            home_dir,
            e
        );
        PathResolveError::HomeDirectoryNotFound
    })?;

    let resolved = resolve_path_internal(cwd, &home_canon, path)?;

    match canonicalize_and_validate(&resolved, &home_canon, &input_desc, allow_symlinks) {
        Ok(canon) => Ok(canon),
        Err(PathResolveError::SymlinkNotAllowed) if allow_symlinks => {
            validate_symlink_chain(&resolved, &home_canon, &input_desc)
        }
        Err(PathResolveError::CanonicalizeFailed) => {
            validate_parent_and_build_path(&resolved, &home_canon, &input_desc)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home() -> tempfile::TempDir {
        tempfile::tempdir().expect("创建临时目录失败")
    }

    #[test]
    fn test_is_absolute_ftp_path() {
        assert!(is_absolute_ftp_path("/home/user"));
        assert!(is_absolute_ftp_path("\\home\\user"));
        assert!(is_absolute_ftp_path("/"));
        assert!(!is_absolute_ftp_path("relative/path"));
        assert!(!is_absolute_ftp_path(""));
    }

    #[test]
    fn test_is_valid_path_component_common() {
        assert!(is_valid_path_component(std::ffi::OsStr::new("valid_name")));
        assert!(is_valid_path_component(std::ffi::OsStr::new("..")));
        assert!(is_valid_path_component(std::ffi::OsStr::new(".")));
        assert!(!is_valid_path_component(std::ffi::OsStr::new("")));
        assert!(!is_valid_path_component(std::ffi::OsStr::new("  ")));
    }

    #[cfg(windows)]
    #[test]
    fn test_is_valid_path_component_windows() {
        assert!(!is_valid_path_component(std::ffi::OsStr::new(
            "invalid:name"
        )));
        for reserved in ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"] {
            assert!(!is_valid_path_component(std::ffi::OsStr::new(reserved)));
        }
        assert!(is_valid_path_component(std::ffi::OsStr::new("con1")));
        for invalid in ["file<name", "file>name", "file\"name", "file|name"] {
            assert!(!is_valid_path_component(std::ffi::OsStr::new(invalid)));
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn test_is_valid_path_component_unix_allows_colon() {
        // Unix 文件名允许冒号与设备名
        assert!(is_valid_path_component(std::ffi::OsStr::new("a:b")));
        assert!(is_valid_path_component(std::ffi::OsStr::new("CON")));
    }

    #[test]
    fn test_to_ftp_path() {
        let home = Path::new("share_test");
        assert_eq!(to_ftp_path(Path::new("share_test/file.txt"), home).unwrap(), "/file.txt");
        assert_eq!(to_ftp_path(Path::new("share_test"), home).unwrap(), "/");
        assert_eq!(
            to_ftp_path(Path::new("share_test/subdir/file.txt"), home).unwrap(),
            "/subdir/file.txt"
        );
        assert!(to_ftp_path(Path::new("other"), home).is_err());
    }

    #[test]
    fn test_path_starts_with_ignore_case() {
        assert!(path_starts_with_ignore_case(
            Path::new("home/users/Test"),
            Path::new("home/users")
        ));
        #[cfg(windows)]
        assert!(path_starts_with_ignore_case(
            Path::new("C:\\Users\\Test"),
            Path::new("c:\\users")
        ));
        assert!(!path_starts_with_ignore_case(
            Path::new("home/Test"),
            Path::new("data")
        ));
    }

    #[test]
    fn test_paths_equal_ignore_case() {
        assert!(paths_equal_ignore_case("home/test", "home/test"));
        assert!(!paths_equal_ignore_case("home/users", "data/users"));
    }

    #[test]
    fn test_strip_extended_prefix() {
        assert_eq!(
            strip_extended_prefix(Path::new(r"\\?\C:\Users\test")),
            PathBuf::from(r"C:\Users\test")
        );
        assert_eq!(
            strip_extended_prefix(Path::new("plain/path")),
            PathBuf::from("plain/path")
        );
    }

    #[test]
    fn test_resolve_path_internal_lexical() {
        let dir = temp_home();
        let home_canon = dir.path().canonicalize().unwrap();

        // 绝对虚路径锚定到 home
        assert_eq!(
            resolve_path_internal("", &home_canon, "/").unwrap(),
            home_canon
        );
        let abs = resolve_path_internal("", &home_canon, "/subdir/file.txt").unwrap();
        assert!(abs.starts_with(&home_canon));
        assert!(abs.to_string_lossy().contains("subdir"));

        // 相对路径锚定到 home
        let rel = resolve_path_internal("", &home_canon, "file.txt").unwrap();
        assert!(rel.ends_with("file.txt"));

        // 空路径 / "." → home
        assert_eq!(resolve_path_internal("", &home_canon, "").unwrap(), home_canon);
        assert_eq!(resolve_path_internal("", &home_canon, ".").unwrap(), home_canon);
    }

    #[test]
    fn test_resolve_path_internal_rejects_escape_and_invalid() {
        let dir = temp_home();
        let home_canon = dir.path().canonicalize().unwrap();

        // cwd 越界
        assert_eq!(
            resolve_path_internal("/etc", &home_canon, "x").unwrap_err(),
            PathResolveError::PathEscape
        );
        // Windows 下盘符/保留名成分非法
        #[cfg(windows)]
        assert_eq!(
            resolve_path_internal("", &home_canon, "/C:/x").unwrap_err(),
            PathResolveError::InvalidPath
        );
        #[cfg(windows)]
        assert_eq!(
            resolve_path_internal("", &home_canon, "CON").unwrap_err(),
            PathResolveError::InvalidPath
        );
    }

    #[test]
    fn test_build_safe_path_parent_escape_and_depth() {
        let dir = temp_home();
        let home_canon = dir.path().canonicalize().unwrap();

        // `..` 逃出 home
        let escaped = home_canon.join("..").join("..");
        assert_eq!(
            build_safe_path(&home_canon, &escaped, "test").unwrap_err(),
            PathResolveError::PathEscape
        );

        // 超深路径
        let mut deep = home_canon.clone();
        for _ in 0..70 {
            deep = deep.join("a");
        }
        assert_eq!(
            build_safe_path(&home_canon, &deep, "test").unwrap_err(),
            PathResolveError::PathTooDeep
        );

        // 正常路径
        let normal = home_canon.join("sub").join("file.txt");
        assert_eq!(
            build_safe_path(&home_canon, &normal, "test").unwrap(),
            normal
        );
    }

    #[test]
    fn test_safe_resolve_path_resolves_within_home() {
        let dir = temp_home();
        std::fs::create_dir(dir.path().join("docs")).unwrap();
        std::fs::write(dir.path().join("docs/a.txt"), b"x").unwrap();
        let home = dir.path().to_string_lossy().to_string();

        let resolved = safe_resolve_path(&home, &home, "docs/a.txt", false).unwrap();
        assert!(resolved.ends_with("docs/a.txt"));
        assert!(resolved.starts_with(dir.path().canonicalize().unwrap()));

        // `..` 归一化不越界
        let norm = safe_resolve_path(&home, &home, "/docs/../a.txt", false).unwrap();
        assert!(norm.ends_with("a.txt"));
    }

    #[test]
    fn test_safe_resolve_path_rejects_escape_above_home() {
        let dir = temp_home();
        let home = dir.path().to_string_lossy().to_string();

        assert!(safe_resolve_path(&home, &home, "/..", false).is_err());
        assert!(safe_resolve_path(&home, &home, "/a/../../x", false).is_err());
        assert!(safe_resolve_path(&home, &home, "../../../../etc/passwd", false).is_err());
    }

    #[test]
    fn test_safe_resolve_path_creates_new_file_under_home() {
        let dir = temp_home();
        std::fs::create_dir(dir.path().join("newdir")).unwrap();
        let home = dir.path().to_string_lossy().to_string();

        // 目标文件不存在但父目录存在 → 通过父目录校验返回拼接路径
        let new_file = safe_resolve_path(&home, &home, "newdir/new.txt", false).unwrap();
        assert!(new_file.ends_with("new.txt"));

        // 父目录不存在 → NotFound（不自动创建中间目录）
        assert_eq!(
            safe_resolve_path(&home, &home, "nodir/new.txt", false).unwrap_err(),
            PathResolveError::NotFound
        );
    }

    #[test]
    fn test_safe_resolve_path_rejects_symlink_escape() {
        let dir = temp_home();
        let home = dir.path().to_string_lossy().to_string();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), b"s").unwrap();

        let link = dir.path().join("leak");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(outside.path(), &link).unwrap();

        // allow_symlinks=false：链上含符号链接直接拒绝
        assert!(safe_resolve_path(&home, &home, "leak/secret.txt", false).is_err());
        // allow_symlinks=true：链校验发现目标越狱仍拒绝
        assert!(safe_resolve_path(&home, &home, "leak/secret.txt", true).is_err());
    }

    #[test]
    fn test_safe_resolve_path_deep_nonexistent_is_not_found() {
        let dir = temp_home();
        let home = dir.path().to_string_lossy().to_string();
        let deep = (0..70).map(|_| "a").collect::<Vec<_>>().join("/");
        // 父目录不存在 → NotFound（深度限制由 build_safe_path 保证）
        assert_eq!(
            safe_resolve_path(&home, &home, &deep, false).unwrap_err(),
            PathResolveError::NotFound
        );
    }

    #[test]
    fn test_path_resolve_error_display() {
        assert_eq!(
            format!("{}", PathResolveError::PathEscape),
            "Path escape detected"
        );
        assert_eq!(
            format!("{}", PathResolveError::NotADirectory),
            "Path is not a directory"
        );
        assert_eq!(format!("{}", PathResolveError::NotFound), "Path not found");
        assert_eq!(
            format!("{}", PathResolveError::PathTooDeep),
            "Path depth exceeds maximum limit"
        );
        assert_eq!(
            format!("{}", PathResolveError::HomeDirectoryNotFound),
            "Home directory not found"
        );
        assert_eq!(
            format!("{}", PathResolveError::CanonicalizeFailed),
            "Path canonicalization failed"
        );
        assert_eq!(format!("{}", PathResolveError::InvalidPath), "Invalid path");
        assert_eq!(
            format!("{}", PathResolveError::SymlinkNotAllowed),
            "Symlinks not allowed"
        );
        assert_eq!(
            format!("{}", PathResolveError::PathNotUnderHome),
            "Path not under home directory"
        );
    }

    #[test]
    fn test_path_resolve_error_is_copy() {
        let err = PathResolveError::InvalidPath;
        let copied = err;
        assert_eq!(err, copied);
    }
}
