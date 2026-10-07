//! 上流への接続の制限（同時接続数・1 秒あたりの新規接続数）。
//! 枠の空きを待つ接続があれば、keep-alive で使っていない上流接続に閉じてもらう。
//! 待っている間も設定を読み直すので、上限を緩めたり 0（無制限）に戻すとすぐ流れ出す。

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::rules::ConnectionLimits;

/// 待っている間に設定を読み直す間隔
const RECHECK: Duration = Duration::from_millis(200);

#[derive(Default)]
pub(crate) struct Limiter {
    state: Mutex<State>,
    /// 枠が返された
    released: Notify,
    /// 枠の空きを待っている接続がある
    idle_wanted: Notify,
}

#[derive(Default)]
struct State {
    active: u32,
    /// 同時接続数の空きを待っている数
    waiting: u32,
    /// 最後に新規接続を出した時刻
    last_issued: Option<Instant>,
}

/// 同時接続数の枠。drop で返す。
pub(crate) struct Permit(Arc<Limiter>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.state.lock().active -= 1;
        self.0.released.notify_one();
    }
}

/// 同時接続数の空き待ちに数えておく（キャンセルされても戻す）。
struct Waiting<'a>(&'a Limiter);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.state.lock().waiting -= 1;
    }
}

enum Blocked {
    /// 同時接続数の上限
    Full,
    /// 頻度の上限。この時刻まで出せない
    Until(Instant),
}

impl Limiter {
    /// 同時接続数の空きと頻度の上限の両方を満たすまで待って枠を返す。
    /// `limits` は毎回呼んで今の設定を読む。
    pub(crate) async fn acquire(this: &Arc<Self>, limits: impl Fn() -> ConnectionLimits) -> Permit {
        loop {
            let limits = limits();
            let released = this.released.notified();
            let blocked = {
                let mut st = this.state.lock();
                let now = Instant::now();
                if limits.max_connections != 0 && st.active >= limits.max_connections {
                    st.waiting += 1;
                    Blocked::Full
                } else if let Some(at) = next_allowed(&st, limits.max_new_per_sec).filter(|at| *at > now) {
                    Blocked::Until(at)
                } else {
                    st.active += 1;
                    st.last_issued = Some(now);
                    return Permit(this.clone());
                }
            };
            match blocked {
                Blocked::Full => {
                    let _waiting = Waiting(this);
                    this.idle_wanted.notify_one();
                    let _ = tokio::time::timeout(RECHECK, released).await;
                }
                Blocked::Until(at) => tokio::time::sleep_until(at.min(Instant::now() + RECHECK)).await,
            }
        }
    }

    /// 枠の空きを待つ接続が出たら完了する（使っていない上流接続を閉じる合図）。
    pub(crate) async fn idle_wanted(&self) {
        loop {
            self.idle_wanted.notified().await;
            // 通知が残っていただけ（待ちはもう解消した）なら閉じない
            if self.state.lock().waiting > 0 {
                return;
            }
        }
    }
}

/// 頻度の上限があれば、次に新規接続を出してよい時刻。
fn next_allowed(st: &State, per_sec: u32) -> Option<Instant> {
    if per_sec == 0 {
        return None;
    }
    st.last_issued.map(|t| t + Duration::from_secs(1) / per_sec)
}

/// 同時接続数の枠を持った上流の TCP 接続。
pub(crate) struct Limited {
    pub(crate) inner: TcpStream,
    pub(crate) _permit: Permit,
}

impl AsyncRead for Limited {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Limited {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_connections: u32, max_new_per_sec: u32) -> ConnectionLimits {
        ConnectionLimits { max_connections, max_new_per_sec }
    }

    #[tokio::test]
    async fn waits_for_free_slot() {
        let l = Arc::new(Limiter::default());
        let a = Limiter::acquire(&l, || limits(2, 0)).await;
        let _b = Limiter::acquire(&l, || limits(2, 0)).await;
        let third = tokio::spawn({
            let l = l.clone();
            async move { Limiter::acquire(&l, || limits(2, 0)).await }
        });
        // 空き待ちが出たら idle の接続に合図が来る
        tokio::time::timeout(Duration::from_secs(1), l.idle_wanted()).await.expect("合図が来ない");
        assert!(!third.is_finished());
        drop(a);
        tokio::time::timeout(Duration::from_secs(1), third).await.expect("枠が返っても進まない").unwrap();
    }

    #[tokio::test]
    async fn spaces_new_connections() {
        let l = Arc::new(Limiter::default());
        let start = Instant::now();
        for _ in 0..3 {
            let _ = Limiter::acquire(&l, || limits(0, 20)).await;
        }
        // 1 件目は即時、以降は 50ms 間隔
        assert!(start.elapsed() >= Duration::from_millis(100), "{:?}", start.elapsed());
        // 無制限なら待たない
        let start = Instant::now();
        for _ in 0..10 {
            let _ = Limiter::acquire(&l, || limits(0, 0)).await;
        }
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn waiters_follow_setting_change() {
        let l = Arc::new(Limiter::default());
        let current = Arc::new(Mutex::new(limits(1, 1)));
        let get = {
            let c = current.clone();
            move || *c.lock()
        };
        let _held = Limiter::acquire(&l, get.clone()).await;
        // 同時接続数の空き待ちと、頻度の上限待ち（1 秒に 1 本）をそれぞれ作る
        let full = tokio::spawn({
            let (l, get) = (l.clone(), get.clone());
            async move { Limiter::acquire(&l, get).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!full.is_finished());
        // 0（無制限）に戻すと、どちらもすぐ進む
        *current.lock() = limits(0, 0);
        let start = Instant::now();
        tokio::time::timeout(Duration::from_secs(1), full).await.expect("同時接続数の待ちが解けない").unwrap();
        for _ in 0..5 {
            let _ = tokio::time::timeout(Duration::from_secs(1), Limiter::acquire(&l, get.clone())).await.expect("頻度の待ちが解けない");
        }
        assert!(start.elapsed() < Duration::from_millis(500), "{:?}", start.elapsed());
    }

    #[tokio::test]
    async fn stale_notification_does_not_close_idle() {
        let l = Arc::new(Limiter::default());
        let held = Limiter::acquire(&l, || limits(1, 0)).await;
        let waiter = tokio::spawn({
            let l = l.clone();
            async move { Limiter::acquire(&l, || limits(1, 0)).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(held);
        drop(waiter.await.unwrap());
        // 待ちが解消した後に残った通知では合図しない
        assert!(tokio::time::timeout(Duration::from_millis(300), l.idle_wanted()).await.is_err());
    }
}
