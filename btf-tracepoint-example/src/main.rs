use aya::{include_bytes_aligned, Bpf};
use aya::{programs::BtfTracePoint, Btf};
use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn};
use tokio::{signal, task};
use btf_tracepoint_example_common::ProcessInfo;


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/btf-tracepoint-example"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/btf-tracepoint-example"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let btf = Btf::from_sys_fs()?;
    let program: &mut BtfTracePoint = bpf.program_mut("sched_process_fork").unwrap().try_into()?;
    program.load("sched_process_fork", &btf)?;
    program.attach()?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS").unwrap()).unwrap();

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const ProcessInfo;
                    let data = unsafe { ptr.read_unaligned() };
                    info!("PID: {}", data.pid);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
