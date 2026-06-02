//! In-process HTTP throughput benchmarks using criterion.
//!
//! Measures framework overhead without network I/O by using
//! `Router::oneshot()` from Tower's `ServiceExt`.
//!
//! Run: `cargo bench -p bench-api`

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use http_body_util::BodyExt;
use tower::ServiceExt;

use bench_api::build_bench_router;

fn bench_noop(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let router = build_bench_router();

    c.bench_function("noop_request", |b| {
        b.to_async(&rt).iter(|| {
            let r = router.clone();
            async move {
                let req = Request::builder()
                    .uri("/bench/noop")
                    .body(Body::empty())
                    .expect("request");
                let resp = r.oneshot(req).await.expect("response");
                assert_eq!(resp.status(), StatusCode::OK);
                black_box(resp);
            }
        });
    });
}

fn bench_json_response(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let router = build_bench_router();

    c.bench_function("json_response", |b| {
        b.to_async(&rt).iter(|| {
            let r = router.clone();
            async move {
                let req = Request::builder()
                    .uri("/bench/json")
                    .body(Body::empty())
                    .expect("request");
                let resp = r.oneshot(req).await.expect("response");
                assert_eq!(resp.status(), StatusCode::OK);
                let body = resp.into_body().collect().await.expect("body").to_bytes();
                black_box(body);
            }
        });
    });
}

fn bench_json_echo(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let router = build_bench_router();

    let payload = serde_json::to_vec(&bench_api::JsonPayload {
        message: "benchmark payload".to_string(),
        count: 12345,
    })
    .expect("serialize");

    c.bench_function("json_echo", |b| {
        b.to_async(&rt).iter(|| {
            let r = router.clone();
            let body = payload.clone();
            async move {
                let req = Request::builder()
                    .method(Method::POST)
                    .uri("/bench/echo")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .expect("request");
                let resp = r.oneshot(req).await.expect("response");
                assert_eq!(resp.status(), StatusCode::OK);
                let body = resp.into_body().collect().await.expect("body").to_bytes();
                black_box(body);
            }
        });
    });
}

criterion_group!(benches, bench_noop, bench_json_response, bench_json_echo);
criterion_main!(benches);
