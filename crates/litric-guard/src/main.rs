//! Console-mode runner. Running as a true Windows Service (SCM) is PLANNED.
//! Usage: litric-guard <protected_dir> [vault_dir]

fn main() {
    use service::{Defender, ServiceConfig};
        let mut a = std::env::args().skip(1);
        let Some(dir) = a.next() else {
            eprintln!("usage: litric-guard <protected_dir> [vault_dir]");
            std::process::exit(2);
        };
        let vault = a.next().unwrap_or_else(|| format!("{}\\.litric-vault", std::env::var("PROGRAMDATA").unwrap_or_else(|_| ".".into())));
        let d = Defender::start(
            ServiceConfig { protected_dirs: vec![dir.clone().into()], vault_dir: vault.into(), trusted_images: vec![], queue_cap: 50_000 },
            Box::new(realtime::windows::Suspender),
        )
        .expect("start failed");
        let h = realtime::windows::watch(&dir, d.pipeline.clone());
        println!("Litric real-time (alert-only: file events carry no process id yet) watching {dir}");
        let mut last_tick = service::now_ms();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let now = service::now_ms();
            if now - last_tick >= 5 * 60 * 1000 {
                last_tick = now;
                match d.tick(now) {
                    Ok(t) => eprintln!("snapshot tick: {t:?}"),
                    Err(e) => eprintln!("snapshot tick FAILED (protection DEGRADED): {e}"),
                }
            }
            let s = d.status();
            if s.degraded || s.incidents > 0 {
                eprintln!("{s:?}");
            }
            if h.is_finished() {
                eprintln!("watcher stopped: protection DEGRADED");
                std::process::exit(1);
            }
        }
}
