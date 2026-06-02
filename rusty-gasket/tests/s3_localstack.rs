//! Integration tests for `S3ObjectStore` against LocalStack S3.
//!
//! Spins up LocalStack via testcontainers and exercises the full round trip:
//! put, get, head (present + absent), list-by-prefix, presigned URL, and the
//! streaming `download_response` helper.

#![cfg(feature = "s3")]
#![allow(clippy::unwrap_used, clippy::panic, clippy::print_stderr)]

use std::time::Duration;

use axum::http::StatusCode;
use bytes::Bytes;
use rusty_gasket::aws::S3ObjectStore;

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .args(["info"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

async fn wait_for_localstack_ready(endpoint: &str) {
    let health_url = format!("{endpoint}/_localstack/health");
    for attempt in 0..30 {
        if let Ok(resp) = reqwest::get(&health_url).await
            && resp.status().is_success()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200 * (attempt + 1))).await;
    }
    panic!("LocalStack did not become ready within timeout");
}

async fn s3_client(endpoint: &str) -> aws_sdk_s3::Client {
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-east-1"))
        .endpoint_url(endpoint)
        .credentials_provider(aws_credential_types::Credentials::new(
            "test",
            "test",
            None,
            None,
            "localstack",
        ))
        .load()
        .await;
    // LocalStack S3 requires path-style addressing (bucket in the path, not host).
    let s3_conf = aws_sdk_s3::config::Builder::from(&config)
        .force_path_style(true)
        .build();
    aws_sdk_s3::Client::from_conf(s3_conf)
}

#[tokio::test]
#[serial_test::file_serial(docker)]
async fn s3_object_store_round_trip() {
    if !docker_available() {
        eprintln!("Skipping: Docker not available");
        return;
    }
    use testcontainers::runners::AsyncRunner;
    use testcontainers_modules::localstack::LocalStack;

    let container = LocalStack::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(4566).await.unwrap();
    let endpoint = format!("http://127.0.0.1:{port}");
    wait_for_localstack_ready(&endpoint).await;

    let client = s3_client(&endpoint).await;
    client
        .create_bucket()
        .bucket("releases")
        .send()
        .await
        .unwrap();

    let store = S3ObjectStore::new(client, "releases");
    assert_eq!(store.bucket(), "releases");

    // put + get
    let body = Bytes::from_static(b"binary-payload-v1");
    store
        .put(
            "releases/v1/gocode-dev",
            body.clone(),
            Some("application/octet-stream"),
        )
        .await
        .unwrap();
    let got = store.get("releases/v1/gocode-dev").await.unwrap();
    assert_eq!(got, body);

    // head present
    let meta = store.head("releases/v1/gocode-dev").await.unwrap().unwrap();
    assert_eq!(meta.content_length, Some(body.len() as u64));
    assert_eq!(
        meta.content_type.as_deref(),
        Some("application/octet-stream")
    );

    // head absent
    assert!(store.head("releases/v1/missing").await.unwrap().is_none());

    // list by prefix
    store
        .put("releases/v2/gocode-dev", Bytes::from_static(b"v2"), None)
        .await
        .unwrap();
    let mut keys = store.list("releases/").await.unwrap();
    keys.sort();
    assert_eq!(
        keys,
        vec!["releases/v1/gocode-dev", "releases/v2/gocode-dev"]
    );

    // presigned URL is well-formed and references the object
    let url = store
        .presigned_get("releases/v1/gocode-dev", Duration::from_secs(60))
        .await
        .unwrap();
    assert!(
        url.contains("releases/v1/gocode-dev"),
        "presigned url: {url}"
    );

    // streaming download response
    let resp = store.download_response("releases/v1/gocode-dev").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let collected = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(collected, body);

    // download of a missing object -> 404
    let missing = store.download_response("releases/nope").await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}
