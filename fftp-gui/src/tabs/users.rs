//! 用户页：结构化用户管理（列表 + 新增/编辑/改密/删除内联对话框）
//!
//! 本地维护用户表（`Core::users`）并刷新列表模型；对话框表单为
//! `UsersState` 的 in-out 属性，提交时校验并经 `GetUsers` → 应用 →
//! `SaveUsers` 以 `users.json` 原文整体提交（后端是唯一写入者）。
//! 新用户口令在 GUI 侧生成 Argon2id PHC 哈希（参数与 `UserManager`
//! 内部实现一致：`m=65536,t=3,p=4,len=32`）。

use std::collections::BTreeMap;
use std::rc::Rc;

use argon2::password_hash::PasswordHasher;
use argon2::{Algorithm, Argon2, Version};
use chrono::Utc;
use fftp_common::users::{is_safe_username, Permissions, User, UserManager};
use fftp_ipc::protocol::Command;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::app::{dispatch, relay, wire0, wire1, SharedCore, UiWeak};
use crate::ipc_service::{self, IpcConn, IpcError, TextContent};
use crate::{AppWindow, UserRow, UsersState};

/// 新增/编辑用户表单（对话框属性的 Rust 投影，提交时构造）
#[derive(Debug, Clone, Default)]
pub struct UserForm {
    /// 编辑目标用户名（`None` = 新增）
    pub editing: Option<String>,
    /// 用户名
    pub username: String,
    /// 口令（仅新增必填）
    pub password: String,
    /// 主目录
    pub home_dir: String,
    /// 权限
    pub permissions: Permissions,
    /// 管理员
    pub is_admin: bool,
    /// 启用
    pub enabled: bool,
    /// 配额文本（MB，空 = 不限）
    pub quota_mb: String,
    /// 限速文本（KB/s，空 = 不限）
    pub speed_limit_kbps: String,
}

impl UserForm {
    /// 从既有用户构造编辑表单
    #[must_use]
    pub fn for_edit(user: &User) -> Self {
        Self {
            editing: Some(user.username.clone()),
            username: user.username.clone(),
            password: String::new(),
            home_dir: user.home_dir.clone(),
            permissions: user.permissions,
            is_admin: user.is_admin,
            enabled: user.enabled,
            quota_mb: user
                .permissions
                .quota_mb
                .map_or_else(String::new, |v| v.to_string()),
            speed_limit_kbps: user
                .permissions
                .speed_limit_kbps
                .map_or_else(String::new, |v| v.to_string()),
        }
    }

    /// 校验表单并构造 [`User`]
    ///
    /// `existing` 为编辑目标的既有记录（新增时为 `None`）。
    ///
    /// # Errors
    /// 用户名非法/重名、新增时口令为空、主目录为空或配额/限速数值非法时返回错误
    pub fn build(&self, existing: Option<&User>) -> Result<User, String> {
        if !is_safe_username(&self.username) {
            return Err(
                "用户名不合法：仅允许字母数字、下划线与连字符，长度 1~64，且以字母数字或下划线开头"
                    .to_owned(),
            );
        }
        if self.home_dir.trim().is_empty() {
            return Err("主目录不能为空".to_owned());
        }
        let mut permissions = self.permissions;
        permissions.quota_mb = parse_optional(&self.quota_mb, "配额（MB）")?;
        permissions.speed_limit_kbps = parse_optional(&self.speed_limit_kbps, "限速（KB/s）")?;

        if let Some(user) = existing {
            Ok(User {
                home_dir: self.home_dir.trim().to_owned(),
                permissions,
                is_admin: self.is_admin,
                enabled: self.enabled,
                ..user.clone()
            })
        } else {
            if self.password.is_empty() {
                return Err("新用户口令不能为空".to_owned());
            }
            Ok(User {
                username: self.username.trim().to_owned(),
                password_hash: hash_password(&self.password)?,
                home_dir: self.home_dir.trim().to_owned(),
                permissions,
                created_at: Utc::now(),
                last_login: None,
                enabled: self.enabled,
                is_admin: self.is_admin,
            })
        }
    }
}

/// 用户库变更（`GetUsers` → 应用 → `SaveUsers` 整体提交）
#[derive(Debug, Clone)]
enum UserOp {
    /// 新增/覆盖用户
    Upsert(User),
    /// 删除用户
    Delete(String),
    /// 修改口令（已哈希）
    SetPassword { username: String, hash: String },
}

/// 目录辅助操作
#[derive(Debug, Clone, Copy)]
enum DirOp {
    /// 创建目录
    Create,
    /// 设置目录权限
    Perms,
    /// 初始化用户目录
    Ensure,
}

/// 回调接线
pub fn wire(weak: &UiWeak, core: &SharedCore) {
    let ui = weak.upgrade().unwrap();
    let state = ui.global::<UsersState>();
    state.on_new_user(wire0(weak, core, on_new_user));
    state.on_edit_user(wire1(weak, core, on_edit_user));
    state.on_delete_user(wire1(weak, core, on_delete_user));
    state.on_change_password(wire1(weak, core, on_change_password));
    state.on_close_dialog(wire0(weak, core, |ui, _core| {
        ui.global::<UsersState>().set_dialog_kind(0);
    }));
    state.on_submit(wire0(weak, core, on_submit));
    state.on_confirm_delete(wire0(weak, core, on_confirm_delete));
    state.on_create_dir(wire0(weak, core, |ui, core| dir_op(ui, core, DirOp::Create)));
    state.on_setup_perms(wire0(weak, core, |ui, core| dir_op(ui, core, DirOp::Perms)));
    state.on_ensure_dirs(wire0(weak, core, |ui, core| dir_op(ui, core, DirOp::Ensure)));
    state.on_use_suggestion(wire1(weak, core, on_use_suggestion));
    state.on_username_changed(wire0(weak, core, update_suggestions));
}

/// 载入 `users.json` 原文并刷新列表（初始状态/保存响应共用）
pub fn load(ui: &AppWindow, core: &SharedCore, content: &str) {
    let state = ui.global::<UsersState>();
    match parse_users(content) {
        Ok(users) => {
            core.lock().unwrap().users = users;
            state.set_error("".into());
        }
        Err(e) => state.set_error(e.into()),
    }
    state.set_info("".into());
    refresh_model(ui, core);
}

/// 由本地用户表重建列表模型（按用户名排序）
pub fn refresh_model(ui: &AppWindow, core: &SharedCore) {
    let rows: Vec<UserRow> = {
        let c = core.lock().unwrap();
        c.users
            .values()
            .map(|user| UserRow {
                username: user.username.clone().into(),
                enabled: user.enabled,
                admin: user.is_admin,
                home: user.home_dir.clone().into(),
                quota: limit_text(user.permissions.quota_mb, "MB").into(),
                limit: limit_text(user.permissions.speed_limit_kbps, "KB/s").into(),
            })
            .collect()
    };
    ui.global::<UsersState>()
        .set_users(ModelRc::from(Rc::new(VecModel::from(rows))));
}

/// 打开新增用户对话框（默认启用，权限取 [`Permissions::default`]）
fn on_new_user(ui: &AppWindow, core: &SharedCore) {
    let state = ui.global::<UsersState>();
    state.set_dialog_kind(1);
    state.set_editing("".into());
    state.set_username("".into());
    state.set_password("".into());
    state.set_home_dir("".into());
    state.set_is_admin(false);
    state.set_enabled(true);
    state.set_quota("".into());
    state.set_speed("".into());
    set_perms(ui, &Permissions::default());
    state.set_form_error("".into());
    update_suggestions(ui, core);
}

/// 打开编辑对话框
fn on_edit_user(ui: &AppWindow, core: &SharedCore, name: SharedString) {
    let name = String::from(name);
    let user = core.lock().unwrap().users.get(&name).cloned();
    let Some(user) = user else {
        ui.global::<UsersState>()
            .set_error(format!("用户不存在：{name}").into());
        return;
    };
    let form = UserForm::for_edit(&user);
    let state = ui.global::<UsersState>();
    state.set_dialog_kind(1);
    state.set_editing(form.editing.clone().unwrap_or_default().into());
    state.set_username(form.username.clone().into());
    state.set_password(form.password.clone().into());
    state.set_home_dir(form.home_dir.clone().into());
    state.set_is_admin(form.is_admin);
    state.set_enabled(form.enabled);
    state.set_quota(form.quota_mb.clone().into());
    state.set_speed(form.speed_limit_kbps.clone().into());
    set_perms(ui, &form.permissions);
    state.set_form_error("".into());
    update_suggestions(ui, core);
}

/// 打开改密对话框
fn on_change_password(ui: &AppWindow, _core: &SharedCore, name: SharedString) {
    let state = ui.global::<UsersState>();
    state.set_dialog_kind(2);
    state.set_pwd_username(name);
    state.set_pwd_new("".into());
    state.set_pwd_confirm("".into());
    state.set_pwd_error("".into());
}

/// 打开删除确认
fn on_delete_user(ui: &AppWindow, _core: &SharedCore, name: SharedString) {
    let state = ui.global::<UsersState>();
    state.set_dialog_kind(3);
    state.set_del_username(name);
}

/// 权限位写入 UI
fn set_perms(ui: &AppWindow, perms: &Permissions) {
    let state = ui.global::<UsersState>();
    state.set_perm_read(perms.can_read);
    state.set_perm_write(perms.can_write);
    state.set_perm_delete(perms.can_delete);
    state.set_perm_list(perms.can_list);
    state.set_perm_mkdir(perms.can_mkdir);
    state.set_perm_rmdir(perms.can_rmdir);
    state.set_perm_rename(perms.can_rename);
    state.set_perm_append(perms.can_append);
}

/// 从 UI 读回权限位
fn read_perms(ui: &AppWindow) -> Permissions {
    let state = ui.global::<UsersState>();
    Permissions {
        can_read: state.get_perm_read(),
        can_write: state.get_perm_write(),
        can_delete: state.get_perm_delete(),
        can_list: state.get_perm_list(),
        can_mkdir: state.get_perm_mkdir(),
        can_rmdir: state.get_perm_rmdir(),
        can_rename: state.get_perm_rename(),
        can_append: state.get_perm_append(),
        ..Permissions::default()
    }
}

/// 对话框属性 → 表单投影
fn form_from_ui(ui: &AppWindow) -> UserForm {
    let state = ui.global::<UsersState>();
    let editing = state.get_editing().to_string();
    UserForm {
        editing: (!editing.is_empty()).then_some(editing),
        username: state.get_username().to_string(),
        password: state.get_password().to_string(),
        home_dir: state.get_home_dir().to_string(),
        permissions: read_perms(ui),
        is_admin: state.get_is_admin(),
        enabled: state.get_enabled(),
        quota_mb: state.get_quota().to_string(),
        speed_limit_kbps: state.get_speed().to_string(),
    }
}

/// 提交对话框（新增/编辑与改密共用入口）
fn on_submit(ui: &AppWindow, core: &SharedCore) {
    let state = ui.global::<UsersState>();
    match state.get_dialog_kind() {
        1 => {
            let form = form_from_ui(ui);
            let existing = form
                .editing
                .as_ref()
                .and_then(|name| core.lock().unwrap().users.get(name).cloned());
            match form.build(existing.as_ref()) {
                Ok(user) => {
                    if form.editing.is_none()
                        && core.lock().unwrap().users.contains_key(&user.username)
                    {
                        state.set_form_error(format!("用户已存在：{}", user.username).into());
                        return;
                    }
                    send_op(ui, core, UserOp::Upsert(user));
                }
                Err(e) => state.set_form_error(e.into()),
            }
        }
        2 => {
            let password = state.get_pwd_new().to_string();
            if password.is_empty() {
                state.set_pwd_error("新口令不能为空".into());
                return;
            }
            if password != state.get_pwd_confirm().as_ref() {
                state.set_pwd_error("两次输入的口令不一致".into());
                return;
            }
            match hash_password(&password) {
                Ok(hash) => send_op(
                    ui,
                    core,
                    UserOp::SetPassword {
                        username: state.get_pwd_username().to_string(),
                        hash,
                    },
                ),
                Err(e) => state.set_pwd_error(e.into()),
            }
        }
        _ => {}
    }
}

/// 确认删除
fn on_confirm_delete(ui: &AppWindow, core: &SharedCore) {
    let username = ui.global::<UsersState>().get_del_username().to_string();
    if username.is_empty() {
        return;
    }
    send_op(ui, core, UserOp::Delete(username));
}

/// 提交变更（经 `GetUsers` → 应用 → `SaveUsers`）
fn send_op(ui: &AppWindow, core: &SharedCore, op: UserOp) {
    let Some(conn) = core.lock().unwrap().ipc.conn().cloned() else {
        ui.global::<UsersState>()
            .set_error("未连接 fftpd，无法保存".into());
        return;
    };
    let state = ui.global::<UsersState>();
    state.set_busy(true);
    state.set_error("".into());
    state.set_info("".into());
    dispatch(ui.as_weak(), core, apply_op(conn, op), on_saved);
}

/// `SaveUsers` 响应：刷新本地用户表并关闭对话框
fn on_saved(ui: &AppWindow, core: &SharedCore, result: Result<String, IpcError>) {
    let state = ui.global::<UsersState>();
    state.set_busy(false);
    match result {
        Ok(content) => {
            match parse_users(&content) {
                Ok(users) => {
                    core.lock().unwrap().users = users;
                }
                Err(e) => {
                    state.set_error(e.into());
                    return;
                }
            }
            state.set_dialog_kind(0);
            state.set_error("".into());
            state.set_info("用户库已保存".into());
            refresh_model(ui, core);
        }
        Err(e) => {
            state.set_error(e.message().into());
            relay(ui, core, &e);
        }
    }
}

/// 目录辅助操作
fn dir_op(ui: &AppWindow, core: &SharedCore, op: DirOp) {
    let Some(conn) = core.lock().unwrap().ipc.conn().cloned() else {
        ui.global::<UsersState>()
            .set_error("未连接 fftpd，无法操作目录".into());
        return;
    };
    let state = ui.global::<UsersState>();
    let path = state.get_home_dir().trim().to_owned();
    if matches!(op, DirOp::Create | DirOp::Perms) && path.is_empty() {
        state.set_error("请先填写主目录".into());
        return;
    }
    let (cmd, ok_text) = match op {
        DirOp::Create => (Command::CreateUserDirectory { path }, "目录已创建"),
        DirOp::Perms => (Command::SetupDirectoryPermissions { path }, "目录权限已设置"),
        DirOp::Ensure => (Command::EnsureUserDirectories, "用户目录已初始化"),
    };
    state.set_busy(true);
    state.set_error("".into());
    state.set_info("".into());
    dispatch(
        ui.as_weak(),
        core,
        async move { ipc_service::request_ok(conn, cmd).await },
        move |ui, core, result: Result<(), IpcError>| on_dir_done(ui, core, result, ok_text),
    );
}

/// 目录辅助操作响应
fn on_dir_done(ui: &AppWindow, core: &SharedCore, result: Result<(), IpcError>, ok_text: &str) {
    let state = ui.global::<UsersState>();
    state.set_busy(false);
    match result {
        Ok(()) => {
            state.set_error("".into());
            state.set_info(ok_text.into());
        }
        Err(e) => {
            state.set_error(e.message().into());
            relay(ui, core, &e);
        }
    }
}

/// 点击建议目录：按缩写找回完整路径填入主目录
fn on_use_suggestion(ui: &AppWindow, core: &SharedCore, short: SharedString) {
    let short = String::from(short);
    let full = {
        let c = core.lock().unwrap();
        c.suggestion_map
            .iter()
            .find(|(s, _)| *s == short)
            .map(|(_, full)| full.clone())
    };
    if let Some(dir) = full {
        ui.global::<UsersState>().set_home_dir(dir.into());
    }
}

/// 按当前用户名刷新建议目录（新增/编辑打开与用户名编辑时触发）
fn update_suggestions(ui: &AppWindow, core: &SharedCore) {
    let username = ui.global::<UsersState>().get_username().to_string();
    let dirs = suggested_dirs(&username);
    let shorts: Vec<SharedString> = dirs.iter().map(|d| shorten(d, 24).into()).collect();
    core.lock().unwrap().suggestion_map =
        shorts.iter().map(SharedString::to_string).zip(dirs).collect();
    ui.global::<UsersState>()
        .set_suggestions(ModelRc::from(Rc::new(VecModel::from(shorts))));
}

/// 建议的主目录候选（本地计算，参考旧版 Linux GUI 的 `suggested_dirs`）
fn suggested_dirs(username: &str) -> Vec<String> {
    let mut dirs = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        let base = std::path::PathBuf::from(&home);
        dirs.push(home);
        for sub in ["Desktop", "Documents", "Downloads"] {
            let path = base.join(sub);
            if path.is_dir() {
                dirs.push(path.to_string_lossy().into_owned());
            }
        }
        dirs.push(base.join(format!("ftp-{username}")).to_string_lossy().into_owned());
    }
    dirs.push(format!("/srv/ftp/{username}"));
    dirs.push(format!("/var/ftp/{username}"));
    dirs
}

/// 路径缩写展示
fn shorten(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let tail: String = s.chars().rev().take(max.saturating_sub(1)).collect();
        format!("…{}", tail.chars().rev().collect::<String>())
    }
}

/// 配额/限速展示文本
fn limit_text(value: Option<u64>, unit: &str) -> String {
    match value {
        Some(v) => format!("{v} {unit}"),
        None => "不限".to_owned(),
    }
}

/// 解析可选数值（空 = 不限）
fn parse_optional(value: &str, label: &str) -> Result<Option<u64>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .parse::<u64>()
        .map(Some)
        .map_err(|_| format!("{label}不是合法数字：{trimmed}"))
}

/// 生成 Argon2id PHC 口令哈希
///
/// 参数与 [`UserManager`] 内部实现一致（`m=65536,t=3,p=4,len=32`）；
/// 后者未暴露公开哈希接口，故 GUI 侧按同参数生成。
fn hash_password(password: &str) -> Result<String, String> {
    let params = argon2::Params::new(65536, 3, 4, Some(32))
        .map_err(|e| format!("口令哈希参数非法：{e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| format!("口令哈希失败：{e}"))
}

/// 解析 `users.json` 原文为本地用户表
fn parse_users(content: &str) -> Result<BTreeMap<String, User>, String> {
    let manager: UserManager =
        serde_json::from_str(content).map_err(|e| format!("用户库解析失败：{e}"))?;
    Ok(manager
        .get_users()
        .iter()
        .map(|(name, user)| (name.clone(), user.clone()))
        .collect())
}

/// 把 [`User`] 写回 [`UserManager`]（内部映射字段私有，经 JSON 往返完成）
fn upsert_user(manager: &UserManager, user: &User) -> Result<UserManager, IpcError> {
    let mut value = serde_json::to_value(manager)
        .map_err(|e| IpcError::Request(format!("用户库序列化失败：{e}")))?;
    let users = value
        .get_mut("users")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| IpcError::Request("用户库结构不符合预期".to_owned()))?;
    let serialized =
        serde_json::to_value(user).map_err(|e| IpcError::Request(format!("用户序列化失败：{e}")))?;
    users.insert(user.username.clone(), serialized);
    serde_json::from_value(value).map_err(|e| IpcError::Request(format!("用户库解析失败：{e}")))
}

/// 应用变更：`GetUsers` → 应用 → `SaveUsers` 整体提交
async fn apply_op(conn: IpcConn, op: UserOp) -> Result<String, IpcError> {
    let current = ipc_service::request::<TextContent>(conn.clone(), Command::GetUsers).await?;
    let mut manager: UserManager = serde_json::from_str(&current.content)
        .map_err(|e| IpcError::Request(format!("用户库解析失败：{e}")))?;
    manager = match op {
        UserOp::Upsert(user) => upsert_user(&manager, &user)?,
        UserOp::Delete(username) => {
            manager
                .remove_user(&username)
                .map_err(|e| IpcError::Request(format!("{e:#}")))?;
            manager
        }
        UserOp::SetPassword { username, hash } => {
            let mut user = manager
                .get_user(&username)
                .cloned()
                .ok_or_else(|| IpcError::Request(format!("用户不存在：{username}")))?;
            user.password_hash = hash;
            upsert_user(&manager, &user)?
        }
    };
    let content = serde_json::to_string_pretty(&manager)
        .map_err(|e| IpcError::Request(format!("用户库序列化失败：{e}")))?;
    ipc_service::request::<TextContent>(conn, Command::SaveUsers { content })
        .await
        .map(|c| c.content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_user() -> User {
        User {
            username: "alice".to_owned(),
            password_hash: hash_password("s3cret").unwrap(),
            home_dir: "/srv/ftp/alice".to_owned(),
            permissions: Permissions::full(),
            created_at: Utc::now(),
            last_login: None,
            enabled: true,
            is_admin: false,
        }
    }

    #[test]
    fn hash_password_produces_current_policy_phc() {
        let hash = hash_password("s3cret").unwrap();
        assert!(hash.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));
    }

    #[test]
    fn users_content_roundtrip_via_user_manager() {
        let mut users = BTreeMap::new();
        users.insert("alice".to_owned(), sample_user());

        // 本地表 → UserManager → users.json 原文 → 本地表
        let value = serde_json::json!({ "users": users });
        let manager: UserManager = serde_json::from_value(value).unwrap();
        let content = serde_json::to_string_pretty(&manager).unwrap();
        let parsed = parse_users(&content).unwrap();

        assert_eq!(parsed.len(), 1);
        let alice = parsed.get("alice").unwrap();
        assert_eq!(alice.home_dir, "/srv/ftp/alice");
        assert!(alice.permissions.can_read);
        assert_eq!(alice.permissions.quota_mb, None);
    }

    #[test]
    fn upsert_user_replaces_and_preserves_others() {
        let manager: UserManager =
            serde_json::from_value(serde_json::json!({ "users": { "alice": sample_user() } }))
                .unwrap();
        let mut bob = sample_user();
        bob.username = "bob".to_owned();
        bob.home_dir = "/srv/ftp/bob".to_owned();
        let merged = upsert_user(&manager, &bob).unwrap();
        assert_eq!(merged.get_users().len(), 2);
        assert_eq!(merged.get_user("alice").unwrap().home_dir, "/srv/ftp/alice");
        assert_eq!(merged.get_user("bob").unwrap().home_dir, "/srv/ftp/bob");
    }

    #[test]
    fn build_user_validates_and_keeps_identity() {
        let mut form = UserForm::for_edit(&sample_user());
        form.home_dir = "  ".to_owned();
        assert!(form.build(Some(&sample_user())).is_err());

        let mut form = UserForm::for_edit(&sample_user());
        form.home_dir = "/data/alice".to_owned();
        form.quota_mb = "100".to_owned();
        form.speed_limit_kbps = "512".to_owned();
        let edited = form.build(Some(&sample_user())).unwrap();
        assert_eq!(edited.username, "alice");
        assert_eq!(edited.home_dir, "/data/alice");
        assert_eq!(edited.permissions.quota_mb, Some(100));
        assert_eq!(edited.permissions.speed_limit_kbps, Some(512));

        // 新增：口令必填、用户名必须安全
        let form = UserForm {
            username: "bad name".to_owned(),
            home_dir: "/srv/ftp/x".to_owned(),
            ..UserForm::default()
        };
        assert!(form.build(None).is_err());

        let mut form = UserForm {
            username: "bob".to_owned(),
            home_dir: "/srv/ftp/x".to_owned(),
            // 与新增对话框（on_new_user）一致：默认启用
            enabled: true,
            ..UserForm::default()
        };
        assert!(form.build(None).is_err(), "新用户口令为空应报错");

        form.password = "pw".to_owned();
        let user = form.build(None).unwrap();
        assert_eq!(user.username, "bob");
        assert!(user.enabled);
    }

    #[test]
    fn parse_optional_blank_means_unlimited() {
        assert_eq!(parse_optional("  ", "配额").unwrap(), None);
        assert_eq!(parse_optional("10", "配额").unwrap(), Some(10));
        assert!(parse_optional("x", "配额").is_err());
    }

    #[test]
    fn shorten_keeps_tail_within_limit() {
        assert_eq!(shorten("/srv/ftp/alice", 24), "/srv/ftp/alice");
        let long = "/very/long/home/directory/path/for/user";
        let short = shorten(long, 10);
        assert!(short.starts_with('…'));
        assert!(short.chars().count() <= 10);
        assert!(long.ends_with(short.strip_prefix('…').unwrap()));
    }
}
