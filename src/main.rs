use std::env;
use std::error::Error;
use tokio::prelude::*;
use tokio::time::{delay_for, timeout};
use std::sync::Arc;
use futures::{FutureExt, Stream, StreamExt, TryStreamExt, select, future};
use std::time::{Instant, Duration, SystemTime};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct LocalError{
    msg: String
}

impl std::fmt::Display for LocalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
       write!(f, "errpor")
    }
}

impl Error for LocalError {

}

impl LocalError {
    pub fn new(msg: String) -> Box<dyn Error> {
        Box::new(
        LocalError{
            msg
        })
    }
}



#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = env::args().collect();
    if args.len() <= 1 {
        //Ok(())
        Err(LocalError::new(String::from("Missing ifaces")))
    } else {
        let pcap_config = pcap_async::Config::default();
        println!("Using ifaces {:?}", args);
        println!("Using config {:?}", pcap_config);

        let mut handles: Vec<(String, Arc<pcap_async::Handle>)> = vec![];

        for iface in args.drain(1..) {
            let h = pcap_async::Handle::live_capture(iface.as_str())
                .map_err(|e| LocalError::new(e.to_string()))?;
            handles.push((iface, h));
        }

        let packet_streams: Result<Vec<_>, Box<dyn Error>> = handles
            .iter()
            .map(|(_, handle)| {
                pcap_async::PacketStream::new(pcap_config.clone(), handle.clone())
                    .map_err(|e| LocalError::new(e.to_string()))
            })
            .collect();
        let mut packet_streams = packet_streams?;

        let stream = if packet_streams.len() > 1 {
            println!("Using BridgeStream");
            pcap_async::BridgeStream::new(
                packet_streams,
            )
                .map_err(|e| LocalError::new(e.to_string()))?
                .boxed()
        } else {
            println!("Using Normal stream");
            packet_streams.remove(0).boxed()
        };

        let interval = Duration::from_secs(1);
        let mut s = stream
            .scan((0 as u32, SystemTime::now()), |(seen, lasttime), p| {
            let p = p.unwrap();
            *seen += p.iter().map(|p| p.actual_length()).sum::<u32>();
            match lasttime.elapsed() {
                Ok(elapsed) if elapsed > interval => {
                    let rate = (*seen) as f64 / (elapsed.as_secs() as f64);
                    for (iface, h) in handles.iter() {
                        let stats = h.stats().unwrap();
                        println!("{} Stats====\n ifaceDrop={}\n kDrop={}\n received={}",iface, stats.dropped_by_interface, stats.dropped_by_kernel, stats.received);
                    }
                    println!("Totals: {} in {} ({} bytes/sec)", seen, elapsed.as_millis(), rate);
                    *seen = 0;
                    *lasttime = SystemTime::now();
                },
                _ => {
                },
            }
            future::ready(Some(()))
            }).collect::<Vec<_>>();

        s.await;


        Ok(())
    }

}
