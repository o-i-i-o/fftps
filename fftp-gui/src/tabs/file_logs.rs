//! 文件日志页：文件操作审计日志浏览
//!
//! 经 `GetFileOpLogFiles` 列出审计日志文件、`GetFileOpLogContent` 加载内容，
//! 表格展示 时间/用户/IP/操作/文件/大小/协议/结果，支持按用户与操作过滤
//! （过滤条件变更时从 `Core::filelog_entries` 重建模型）。

use std::rc::Rc;

use fftp_ipc::protocol::{Command, FileOpLogEntry};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::app::{dispatch, relay, wire0, wire1, SharedCore, UiWeak};
use crate::ipc_service::{self, FileOpEntries, IpcError, LogFiles};
use crate::tabs::{file_options, row_index, ui_index, FileOption};
use crate::{AppWindow, FileLogsState, FileOpRow};

/// 文件历史一次加载的条数
const FILE_LOAD_COUNT: u32 = 500;

/// 回调接线
pub fn wire(weak: &UiWeak, core: &SharedCore) {
    let ui = weak.upgrade().unwrap();
    let state = ui.global::<FileLogsState>();
    state.on_refresh(wire0(weak, core, refresh));
    state.on_load(wire0(weak, core, load));
    state.on_select_file(wire1(weak, core, select_file));
    state.on_filter_changed(wire0(weak, core, rebuild));
}

/// 拉取文件列表（进入页面/点击刷新）
pub fn refresh(ui: &AppWindow, core: &SharedCore) {
    let Some(conn) = core.lock().unwrap().ipc.conn().cloned() else {
        ui.global::<FileLogsState>()
            .set_error("未连接 fftpd，无法读取文件日志".into());
        return;
    };
    ui.global::<FileLogsState>().set_loading(true);
    dispatch(
        ui.as_weak(),
        core,
        async move {
            ipc_service::request::<LogFiles>(conn, Command::GetFileOpLogFiles)
                .await
                .map(|r| file_options(&r.files))
        },
        on_files,
    );
}

/// `GetFileOpLogFiles` 响应：更新文件下拉、保持原选中并在变化时自动加载
fn on_files(ui: &AppWindow, core: &SharedCore, result: Result<Vec<FileOption>, IpcError>) {
    let state = ui.global::<FileLogsState>();
    state.set_loading(false);
    let files = match result {
        Ok(files) => files,
        Err(e) => {
            state.set_error(e.message().into());
            relay(ui, core, &e);
            return;
        }
    };
    let names: Vec<SharedString> = files.iter().map(|f| f.name.clone().into()).collect();
    let (selected_idx, need_load) = {
        let mut c = core.lock().unwrap();
        let selected = c
            .filelog_selected
            .clone()
            .filter(|current| files.iter().any(|f| f.path == current.path))
            .or_else(|| files.first().cloned());
        let need_load = selected != c.filelog_selected;
        let idx = selected
            .as_ref()
            .and_then(|sel| files.iter().position(|f| f.path == sel.path))
            .map_or(0, ui_index);
        c.filelog_selected = selected;
        c.filelog_files = files;
        (idx, need_load)
    };
    state.set_file_names(ModelRc::from(Rc::new(VecModel::from(names))));
    state.set_file_idx(selected_idx);
    state.set_error("".into());
    if need_load {
        load(ui, core);
    }
}

/// 选择文件后加载内容
fn select_file(ui: &AppWindow, core: &SharedCore, idx: i32) {
    let option = {
        let mut c = core.lock().unwrap();
        let option = c.filelog_files.get(row_index(idx)).cloned();
        if option.is_some() {
            c.filelog_selected.clone_from(&option);
        }
        option
    };
    if option.is_some() {
        load(ui, core);
    }
}

/// 加载选中文件内容
fn load(ui: &AppWindow, core: &SharedCore) {
    let (conn, path) = {
        let c = core.lock().unwrap();
        (
            c.ipc.conn().cloned(),
            c.filelog_selected.as_ref().map(|f| f.path.clone()),
        )
    };
    let Some(path) = path else {
        return;
    };
    let Some(conn) = conn else {
        ui.global::<FileLogsState>()
            .set_error("未连接 fftpd，无法读取文件日志".into());
        return;
    };
    ui.global::<FileLogsState>().set_loading(true);
    dispatch(
        ui.as_weak(),
        core,
        async move {
            ipc_service::request::<FileOpEntries>(
                conn,
                Command::GetFileOpLogContent {
                    path,
                    count: FILE_LOAD_COUNT,
                },
            )
            .await
            .map(|r| r.entries)
        },
        on_entries,
    );
}

/// `GetFileOpLogContent` 响应：写入缓冲并按过滤条件重建模型
fn on_entries(ui: &AppWindow, core: &SharedCore, result: Result<Vec<FileOpLogEntry>, IpcError>) {
    let state = ui.global::<FileLogsState>();
    state.set_loading(false);
    match result {
        Ok(entries) => {
            core.lock().unwrap().filelog_entries = entries;
            state.set_error("".into());
            rebuild(ui, core);
        }
        Err(e) => {
            state.set_error(e.message().into());
            relay(ui, core, &e);
        }
    }
}

/// 按当前用户/操作过滤条件从缓冲重建展示模型
fn rebuild(ui: &AppWindow, core: &SharedCore) {
    let state = ui.global::<FileLogsState>();
    let user = state.get_user_filter().trim().to_lowercase();
    let op = state.get_op_filter().trim().to_lowercase();
    let rows: Vec<FileOpRow> = {
        let c = core.lock().unwrap();
        c.filelog_entries
            .iter()
            .filter(|entry| {
                (user.is_empty() || entry.username.to_lowercase().contains(&user))
                    && (op.is_empty() || entry.operation.to_lowercase().contains(&op))
            })
            .map(|entry| FileOpRow {
                time: entry.timestamp.clone().into(),
                user: entry.username.clone().into(),
                ip: entry.client_ip.clone().into(),
                op: entry.operation.clone().into(),
                file: entry.file_path.clone().into(),
                size: format_size(entry.file_size).into(),
                protocol: entry.protocol.clone().into(),
                success: entry.success,
            })
            .collect()
    };
    state.set_count(ui_index(rows.len()));
    state.set_entries(ModelRc::from(Rc::new(VecModel::from(rows))));
}

/// 字节数的可读展示（整数运算，避免浮点精度告警）
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{}.{:02} GB", bytes / GB, (bytes % GB) * 100 / GB)
    } else if bytes >= MB {
        format!("{}.{:02} MB", bytes / MB, (bytes % MB) * 100 / MB)
    } else if bytes >= KB {
        format!("{}.{:02} KB", bytes / KB, (bytes % KB) * 100 / KB)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_size_scales_units() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(2048), "2.00 KB");
        assert_eq!(format_size(5 * 1024 * 1024), "5.00 MB");
        assert_eq!(format_size(3 * 1024 * 1024 * 1024), "3.00 GB");
    }
}
