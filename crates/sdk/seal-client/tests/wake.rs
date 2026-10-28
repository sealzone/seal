//! Waking stopped Seal-hosted replicas, against the in-test enclave (`common/fixture.rs`). A
//! binary of its own: it sets `SEAL_WAKE_URL`, which every client in the process then reads.
#![cfg(feature = "sim")]
#![allow(dead_code, unused_imports)]

include!("common/fixture.rs");

#[tokio::test]
async fn wakes_stopped_replicas_and_verifies_whatever_answers() {
    let f = Fixture::new().await;
    // The replica's address, with nothing listening until it is woken.
    let replica = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = replica.local_addr().unwrap();
    let endpoint: url::Url = format!("https://{addr}").parse().unwrap();
    drop(replica);

    // Without a wake URL, nothing answers.
    let err = f.builder().endpoints([endpoint.clone()]).connect().await.err().unwrap();
    assert!(matches!(err, ClientError::Network(_)), "{err}");

    // The wake stand-in starts the replica on its first request.
    let wake = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wake_url = format!("http://{}/api/v1/wake", wake.local_addr().unwrap());
    let woken: Arc<Mutex<Vec<String>>> = Arc::default();
    let (enclave, record) = (f.enclave.clone(), woken.clone());
    tokio::spawn(async move {
        while let Ok((tcp, _)) = wake.accept().await {
            let (enclave, record) = (enclave.clone(), record.clone());
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                let (enclave, record) = (enclave.clone(), record.clone());
                async move {
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    record.lock().unwrap().push(String::from_utf8(body.to_vec()).unwrap());
                    let listener = TcpListener::bind(addr).await.unwrap();
                    let tls = tls_config(&enclave.keys);
                    tokio::spawn(serve(enclave, listener, tls));
                    Ok::<_, hyper::Error>(Response::builder().status(202).body(Full::new(Bytes::new())).unwrap())
                }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tcp), service).await;
        }
    });
    std::env::set_var("SEAL_WAKE_URL", &wake_url);
    let client = f.builder().endpoints([endpoint]).connect().await.unwrap();
    client.signal("edr-alert", Severity::Low).await.unwrap();
    assert_eq!(*woken.lock().unwrap(), [r#"{"tenant":"acme"}"#]);
}
