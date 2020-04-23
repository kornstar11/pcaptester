use std::env;
use std::error::Error;
use tokio::prelude::*;
use tokio::time::{delay_for, timeout};
use std::sync::Arc;
use futures::{FutureExt, Stream, StreamExt, TryStreamExt, select};
use std::time::{Instant, Duration};
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

        let mut handles: Vec<Arc<pcap_async::Handle>> = vec![];

        for iface in args.drain(1..) {
            let h = pcap_async::Handle::live_capture(iface.as_str())
                .map_err(|e| LocalError::new(e.to_string()))?;
            handles.push(h);
        }

        let packet_streams: Result<Vec<_>, Box<dyn Error>> = handles
            .iter()
            .map(|handle| {
                pcap_async::PacketStream::new(pcap_config.clone(), handle.clone())
                    .map_err(|e| LocalError::new(e.to_string()))
            })
            .collect();
        let packet_streams = packet_streams?;
        let stream = pcap_async::BridgeStream::new(
            packet_streams,
        )
            .map_err(|e| LocalError::new(e.to_string()))?
            .boxed();


        // let mut d = delay_for(Duration::from_millis(2000)).map(|any| {
        //     println!("Done");
        //     any
        // }).fuse();
        let mut counter = Arc::new(AtomicUsize::new(0));

        let mut s = stream.map(|p| {
            let c = counter.fetch_add(p.unwrap().len(), Ordering::SeqCst);
            println!("counter {}", c);
            c

        }).collect::<Vec<usize>>();

        let res = timeout(Duration::from_secs(1), s).await;


        // let res = select! {
        //     sv = s => sv,
        //     _ = d => counter.load(Ordering::SeqCst),
        // };

        let final_count = counter.load(Ordering::SeqCst);
        println!("Elapsed: {:?}  {}", res, final_count);


        Ok(())
    }

}
