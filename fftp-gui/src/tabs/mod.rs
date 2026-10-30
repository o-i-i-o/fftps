//! 各功能页逻辑：纯状态与 IPC 封装
//!
//! 视图全部在 ui/*.slint（声明式），本层只保留可测试的业务逻辑
//! （表单/配置转换、IPC 请求流、过滤与格式化辅助）；页面状态经
//! Slint global 属性与 Rust 同步，回调接线在各模块 `wire` 函数。

pub mod about;
pub mod file_logs;
pub mod logs;
pub mod security;
pub mod server;
pub mod service;
pub mod users;

use fftp_ipc::protocol::LogFileInfo;

/// 日志文件下拉选项
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOption {
    /// 文件名
    pub name: String,
    /// 完整路径
    pub path: String,
}

impl FileOption {
    /// 从协议文件信息转换
    #[must_use]
    pub fn from_info(info: &LogFileInfo) -> Self {
        Self {
            name: info.name.clone(),
            path: info.path.clone(),
        }
    }
}

/// 把协议文件列表转换为下拉选项
#[must_use]
pub fn file_options(files: &[LogFileInfo]) -> Vec<FileOption> {
    files.iter().map(FileOption::from_info).collect()
}

/// 解析无符号数值字段
pub(crate) fn parse_num<T: std::str::FromStr>(value: &str, label: &str) -> Result<T, String> {
    value
        .trim()
        .parse::<T>()
        .map_err(|_| format!("{label}不是合法数字：{value}"))
}

/// Slint UI 索引（i32）← Rust 集合长度（usize）
///
/// UI 列表（模型行数、下拉项）规模远小于 i32 上限，回退 `i32::MAX` 仅为兜底。
#[must_use]
pub(crate) fn ui_index(n: usize) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

/// Rust 下标（usize）← Slint UI 索引（i32，来自下拉/表格回调，非负）
///
/// 负值（理论不可达）回退 `usize::MAX`：`get` 未命中、越界比较恒假，退化为「无此行」。
#[must_use]
pub(crate) fn row_index(idx: i32) -> usize {
    usize::try_from(idx).unwrap_or(usize::MAX)
}
