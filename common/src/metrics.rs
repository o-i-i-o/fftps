//! Prometheus 监控指标（docs/design.md §4「指标」：Windows `metrics.rs` 全量迁移）
//!
//! 指标名与旧版保持一致（`wftpg_*` 前缀），已有采集端/面板无需改动。
//! 静态注册改用标准库 `LazyLock`（替代旧版 `lazy_static`）。

use prometheus::{
    Counter, Gauge, HistogramVec, register_counter, register_gauge, register_histogram_vec,
};
use std::sync::LazyLock;
use std::time::Instant;

// ---- 连接指标 ----

/// 总连接数
pub static CONNECTIONS_TOTAL: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!("wftpg_connections_total", "Total number of connections")
        .expect("register wftpg_connections_total")
});

/// 当前活跃连接数
pub static CONNECTIONS_ACTIVE: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(
        "wftpg_connections_active",
        "Number of active connections"
    )
    .expect("register wftpg_connections_active")
});

/// 被拒绝的连接数（IP/连接数限制）
pub static CONNECTIONS_REJECTED: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "wftpg_connections_rejected_total",
        "Number of rejected connections (IP limits)"
    )
    .expect("register wftpg_connections_rejected_total")
});

// ---- FTP 指标 ----

/// 已处理的 FTP 命令数
pub static FTP_COMMANDS_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "wftpg_ftp_commands_total",
        "Total number of FTP commands processed"
    )
    .expect("register wftpg_ftp_commands_total")
});

/// FTP 上传字节数
pub static FTP_UPLOAD_BYTES: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "wftpg_ftp_upload_bytes_total",
        "Total bytes uploaded via FTP"
    )
    .expect("register wftpg_ftp_upload_bytes_total")
});

/// FTP 下载字节数
pub static FTP_DOWNLOAD_BYTES: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "wftpg_ftp_download_bytes_total",
        "Total bytes downloaded via FTP"
    )
    .expect("register wftpg_ftp_download_bytes_total")
});

// ---- SFTP 指标 ----

/// 已处理的 SFTP 命令数
pub static SFTP_COMMANDS_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "wftpg_sftp_commands_total",
        "Total number of SFTP commands processed"
    )
    .expect("register wftpg_sftp_commands_total")
});

/// SFTP 上传字节数
pub static SFTP_UPLOAD_BYTES: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "wftpg_sftp_upload_bytes_total",
        "Total bytes uploaded via SFTP"
    )
    .expect("register wftpg_sftp_upload_bytes_total")
});

/// SFTP 下载字节数
pub static SFTP_DOWNLOAD_BYTES: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "wftpg_sftp_download_bytes_total",
        "Total bytes downloaded via SFTP"
    )
    .expect("register wftpg_sftp_download_bytes_total")
});

// ---- 认证指标 ----

/// 认证成功次数
pub static AUTH_SUCCESS_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "wftpg_auth_success_total",
        "Total successful authentications"
    )
    .expect("register wftpg_auth_success_total")
});

/// 认证失败次数
pub static AUTH_FAILURE_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "wftpg_auth_failure_total",
        "Total failed authentications"
    )
    .expect("register wftpg_auth_failure_total")
});

// ---- 性能指标 ----

/// 命令处理耗时（按 protocol/command 打标签）
pub static COMMAND_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "wftpg_command_duration_seconds",
        "Command processing duration in seconds",
        &["protocol", "command"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("register wftpg_command_duration_seconds")
});

/// 文件传输耗时（按 protocol/operation 打标签）
pub static TRANSFER_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "wftpg_transfer_duration_seconds",
        "File transfer duration in seconds",
        &["protocol", "operation"],
        vec![0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0]
    )
    .expect("register wftpg_transfer_duration_seconds")
});

// ---- 错误指标 ----

/// 错误总数
pub static ERRORS_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!("wftpg_errors_total", "Total number of errors")
        .expect("register wftpg_errors_total")
});

/// 命令执行计时器：drop 时自动观测耗时到 [`COMMAND_DURATION`]
pub struct CommandTimer {
    protocol: &'static str,
    command: &'static str,
    start: Instant,
}

impl CommandTimer {
    #[must_use]
    pub fn new(protocol: &'static str, command: &'static str) -> Self {
        Self {
            protocol,
            command,
            start: Instant::now(),
        }
    }
}

impl Drop for CommandTimer {
    fn drop(&mut self) {
        let duration = self.start.elapsed().as_secs_f64();
        COMMAND_DURATION
            .with_label_values(&[self.protocol, self.command])
            .observe(duration);
    }
}

/// 文件传输计时器：drop 时自动观测耗时到 [`TRANSFER_DURATION`]
pub struct TransferTimer {
    protocol: &'static str,
    operation: &'static str,
    start: Instant,
}

impl TransferTimer {
    #[must_use]
    pub fn new(protocol: &'static str, operation: &'static str) -> Self {
        Self {
            protocol,
            operation,
            start: Instant::now(),
        }
    }
}

impl Drop for TransferTimer {
    fn drop(&mut self) {
        let duration = self.start.elapsed().as_secs_f64();
        TRANSFER_DURATION
            .with_label_values(&[self.protocol, self.operation])
            .observe(duration);
    }
}

/// 记录一次认证成功
pub fn record_auth_success() {
    AUTH_SUCCESS_TOTAL.inc();
}

/// 记录一次认证失败
pub fn record_auth_failure() {
    AUTH_FAILURE_TOTAL.inc();
}

/// 记录一次被拒绝的连接
pub fn record_connection_rejected() {
    CONNECTIONS_REJECTED.inc();
}

/// 记录命令处理（`protocol` 取 `FTP`/`SFTP`）
pub fn record_command(protocol: &str) {
    match protocol {
        "FTP" => FTP_COMMANDS_TOTAL.inc(),
        "SFTP" => SFTP_COMMANDS_TOTAL.inc(),
        _ => {}
    }
}

/// 记录上传字节数（`protocol` 取 `FTP`/`SFTP`）
pub fn record_upload_bytes(protocol: &str, bytes: u64) {
    match protocol {
        "FTP" => FTP_UPLOAD_BYTES.inc_by(bytes as f64),
        "SFTP" => SFTP_UPLOAD_BYTES.inc_by(bytes as f64),
        _ => {}
    }
}

/// 记录下载字节数（`protocol` 取 `FTP`/`SFTP`）
pub fn record_download_bytes(protocol: &str, bytes: u64) {
    match protocol {
        "FTP" => FTP_DOWNLOAD_BYTES.inc_by(bytes as f64),
        "SFTP" => SFTP_DOWNLOAD_BYTES.inc_by(bytes as f64),
        _ => {}
    }
}

/// 记录一次错误
pub fn record_error(_error_type: &str, _protocol: &str) {
    // 旧版即为无标签简化实现，保持一致
    ERRORS_TOTAL.inc();
}

/// 导出全部指标（Prometheus 文本格式）
#[must_use]
pub fn gather_metrics() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();

    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        return format!("Error encoding metrics: {e}");
    }

    String::from_utf8_lossy(&buffer).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_recording_updates_values() {
        CONNECTIONS_ACTIVE.set(5.0);
        assert_eq!(CONNECTIONS_ACTIVE.get(), 5.0);

        let before = AUTH_SUCCESS_TOTAL.get();
        record_auth_success();
        assert_eq!(AUTH_SUCCESS_TOTAL.get(), before + 1.0);

        let before = AUTH_FAILURE_TOTAL.get();
        record_auth_failure();
        assert_eq!(AUTH_FAILURE_TOTAL.get(), before + 1.0);

        let before = ERRORS_TOTAL.get();
        record_error("test", "FTP");
        assert_eq!(ERRORS_TOTAL.get(), before + 1.0);

        let before = CONNECTIONS_REJECTED.get();
        record_connection_rejected();
        assert_eq!(CONNECTIONS_REJECTED.get(), before + 1.0);
    }

    #[test]
    fn upload_download_bytes_accumulate_per_protocol() {
        let ftp_before = FTP_UPLOAD_BYTES.get();
        let sftp_before = SFTP_UPLOAD_BYTES.get();
        record_upload_bytes("FTP", 100);
        record_upload_bytes("SFTP", 200);
        record_upload_bytes("OTHER", 300);
        assert_eq!(FTP_UPLOAD_BYTES.get(), ftp_before + 100.0);
        assert_eq!(SFTP_UPLOAD_BYTES.get(), sftp_before + 200.0);

        let ftp_before = FTP_DOWNLOAD_BYTES.get();
        let sftp_before = SFTP_DOWNLOAD_BYTES.get();
        record_download_bytes("FTP", 10);
        record_download_bytes("SFTP", 20);
        assert_eq!(FTP_DOWNLOAD_BYTES.get(), ftp_before + 10.0);
        assert_eq!(SFTP_DOWNLOAD_BYTES.get(), sftp_before + 20.0);
    }

    #[test]
    fn command_counters_per_protocol() {
        let ftp_before = FTP_COMMANDS_TOTAL.get();
        let sftp_before = SFTP_COMMANDS_TOTAL.get();
        record_command("FTP");
        record_command("SFTP");
        assert_eq!(FTP_COMMANDS_TOTAL.get(), ftp_before + 1.0);
        assert_eq!(SFTP_COMMANDS_TOTAL.get(), sftp_before + 1.0);
    }

    #[test]
    fn timers_observe_on_drop() {
        {
            let _timer = CommandTimer::new("FTP", "RETR");
        }
        {
            let _timer = TransferTimer::new("FTP", "UPLOAD");
        }
    }

    #[test]
    fn gather_metrics_returns_text_format() {
        record_auth_success();
        std::hint::black_box(&*CONNECTIONS_ACTIVE);
        let text = gather_metrics();
        assert!(text.contains("wftpg_auth_success_total"));
        assert!(text.contains("wftpg_connections_active"));
    }

    #[test]
    fn metric_names_match_legacy() {
        // 指标静态量是惰性注册的，先全部强制初始化再导出
        std::hint::black_box((
            &*CONNECTIONS_TOTAL,
            &*CONNECTIONS_ACTIVE,
            &*CONNECTIONS_REJECTED,
            &*FTP_COMMANDS_TOTAL,
            &*FTP_UPLOAD_BYTES,
            &*FTP_DOWNLOAD_BYTES,
            &*SFTP_COMMANDS_TOTAL,
            &*SFTP_UPLOAD_BYTES,
            &*SFTP_DOWNLOAD_BYTES,
            &*AUTH_SUCCESS_TOTAL,
            &*AUTH_FAILURE_TOTAL,
            &*COMMAND_DURATION,
            &*TRANSFER_DURATION,
            &*ERRORS_TOTAL,
        ));

        // HistogramVec 只有在产生标签组合后才出现在导出文本中，先落一组子指标
        COMMAND_DURATION.with_label_values(&["FTP", "TEST"]);
        TRANSFER_DURATION.with_label_values(&["FTP", "TEST"]);

        let text = gather_metrics();
        for name in [
            "wftpg_connections_total",
            "wftpg_connections_active",
            "wftpg_connections_rejected_total",
            "wftpg_ftp_commands_total",
            "wftpg_ftp_upload_bytes_total",
            "wftpg_ftp_download_bytes_total",
            "wftpg_sftp_commands_total",
            "wftpg_sftp_upload_bytes_total",
            "wftpg_sftp_download_bytes_total",
            "wftpg_auth_success_total",
            "wftpg_auth_failure_total",
            "wftpg_command_duration_seconds",
            "wftpg_transfer_duration_seconds",
            "wftpg_errors_total",
        ] {
            assert!(text.contains(name), "指标 {name} 应与旧版命名一致");
        }
    }
}
