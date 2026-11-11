use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError};
use std::time::{SystemTime, UNIX_EPOCH};

/// 全局锁中毒自愈审计计数器 (用于运行期可观测性与诊断验证)
static LOCK_POISON_RECOVERY_COUNT: AtomicU64 = AtomicU64::new(0);

#[inline]
fn record_poison_audit(lock_kind: &str, context: &str) -> u64 {
    let total = LOCK_POISON_RECOVERY_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let thread_name = std::thread::current()
        .name()
        .unwrap_or("unnamed-worker")
        .to_string();

    eprintln!(
        "{{\"level\":\"ERROR\",\"event\":\"LOCK_POISON_RECOVERED\",\"lock_kind\":\"{}\",\"context\":\"{}\",\"thread\":\"{}\",\"ts_ms\":{},\"recovery_total\":{}}}",
        lock_kind,
        context.replace('"', "\\\""),
        thread_name.replace('"', "\\\""),
        ts_ms,
        total
    );
    total
}

/// 获取 Mutex 互斥锁；若前序持锁线程曾发生 Panic 导致 Poisoned，
/// 强制输出结构化错误审计日志并自愈恢复内部状态，严禁静默吞错或返回假默认状态。
///
/// 复杂度: 时间 O(1), 空间 O(1)
#[inline]
pub fn lock_mutex<'a, T>(mutex: &'a Mutex<T>, context: &str) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            record_poison_audit("Mutex", context);
            poisoned.into_inner()
        }
    }
}

/// 非阻塞尝试获取 Mutex 互斥锁；
/// - `WouldBlock` 仅表示当前高并发竞争锁正忙，旁路逻辑返回 `None`；
/// - `Poisoned` 强制触发结构化审计记录并自愈返回内部守卫，绝不因中毒永久丧失写入能力。
///
/// 复杂度: 时间 O(1), 空间 O(1)
#[inline]
pub fn try_lock_mutex<'a, T>(mutex: &'a Mutex<T>, context: &str) -> Option<MutexGuard<'a, T>> {
    match mutex.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::WouldBlock) => None,
        Err(TryLockError::Poisoned(poisoned)) => {
            record_poison_audit("MutexTryLock", context);
            Some(poisoned.into_inner())
        }
    }
}

/// 获取 RwLock 共享读锁；若此前有写线程中毒，记录结构化审计日志并恢复状态守卫。
/// 保证防火墙规则、威胁特征库与协议插件表在极端异常下不会因中毒而退化为空规则放行。
///
/// 复杂度: 时间 O(1), 空间 O(1)
#[inline]
pub fn read_rwlock<'a, T>(rwlock: &'a RwLock<T>, context: &str) -> RwLockReadGuard<'a, T> {
    match rwlock.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            record_poison_audit("RwLockRead", context);
            poisoned.into_inner()
        }
    }
}

/// 获取 RwLock 独占写锁；若前序持锁线程中毒，记录结构化审计日志并自愈恢复可写守卫。
///
/// 复杂度: 时间 O(1), 空间 O(1)
#[inline]
pub fn write_rwlock<'a, T>(rwlock: &'a RwLock<T>, context: &str) -> RwLockWriteGuard<'a, T> {
    match rwlock.write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            record_poison_audit("RwLockWrite", context);
            poisoned.into_inner()
        }
    }
}

/// 获取应用生命周期内累计触发锁中毒自愈次数
#[inline]
pub fn total_lock_recoveries() -> u64 {
    LOCK_POISON_RECOVERY_COUNT.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_mutex_empty_state_and_poison_recovery() {
        let shared = Arc::new(Mutex::new(Vec::<u32>::new()));
        let worker_clone = Arc::clone(&shared);

        // 极限用例 1: 写入半途引发 panic 令 Mutex 中毒，校验后续空集合与既写数据不丢失、不二次崩溃
        let handle = std::thread::spawn(move || {
            let mut g = worker_clone.lock().unwrap();
            g.push(1024);
            panic!("simulated worker panic inside mutex lock");
        });
        assert!(handle.join().is_err());

        let before = total_lock_recoveries();
        {
            let recovered = lock_mutex(&shared, "test_mutex_poison_read");
            assert_eq!(recovered.as_slice(), &[1024]);
        }
        assert!(total_lock_recoveries() >= before + 1);

        // 自愈后仍可安全修改写入（例如清空与追加大量数据）
        {
            let mut recovered_mut = lock_mutex(&shared, "test_mutex_poison_write");
            recovered_mut.clear();
            recovered_mut.extend(0..100);
            assert_eq!(recovered_mut.len(), 100);
        }
    }

    #[test]
    fn test_rwlock_write_poison_read_and_rewrite_recovery() {
        let rules = Arc::new(RwLock::new(vec!["DROP_MALICIOUS".to_string()]));
        let rw_clone = Arc::clone(&rules);

        // 极限用例 2: 写锁期间发生 panic 污染，校验读端不会静默返空也不会 panic 放行
        let handle = std::thread::spawn(move || {
            let mut w = rw_clone.write().unwrap();
            w.push("ALERT_EXFIL".to_string());
            panic!("simulated writer panic inside rwlock");
        });
        assert!(handle.join().is_err());

        let before = total_lock_recoveries();
        {
            let r = read_rwlock(&rules, "test_rwlock_read_after_poison");
            assert_eq!(r.len(), 2);
            assert_eq!(r[0], "DROP_MALICIOUS");
        }
        {
            let mut w = write_rwlock(&rules, "test_rwlock_write_after_poison");
            w.push("RATE_LIMIT".to_string());
            assert_eq!(w.len(), 3);
        }
        assert!(total_lock_recoveries() >= before + 2);
    }

    #[test]
    fn test_try_lock_distinguishes_would_block_vs_poisoned() {
        let state = Arc::new(Mutex::new(0u64));

        // 极限用例 3a: 正常持锁期间 try_lock 应返回 None 且绝不记录中毒自愈事件
        let before = total_lock_recoveries();
        {
            let _held = lock_mutex(&state, "test_try_lock_holder");
            let attempt = try_lock_mutex(&state, "test_try_lock_while_busy");
            assert!(attempt.is_none());
        }
        assert_eq!(total_lock_recoveries(), before);

        // 极限用例 3b: 中毒锁在空闲时执行 try_lock 应能立即识别并自愈恢复
        let worker_clone = Arc::clone(&state);
        let handle = std::thread::spawn(move || {
            let mut g = worker_clone.lock().unwrap();
            *g = 777;
            panic!("simulated panic before releasing mutex");
        });
        assert!(handle.join().is_err());

        let recovered = try_lock_mutex(&state, "test_try_lock_after_poison");
        assert!(recovered.is_some());
        assert_eq!(*recovered.unwrap(), 777);
        assert!(total_lock_recoveries() >= before + 1);
    }
}
