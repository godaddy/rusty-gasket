//! S3 object storage, plus a streaming download helper for HTTP services.
//!
//! [`S3ObjectStore`] wraps an `aws_sdk_s3::Client` bound to one bucket and
//! offers the operations a service typically needs: fetch, store, head, list
//! by prefix, presign a GET URL, and — the reason this lives in the framework
//! rather than each service — turn an object into a *streaming* HTTP response
//! so large files (release binaries, archives) are served without buffering
//! the whole body in memory.

use std::time::Duration;

use axum::body::Body;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use rusty_gasket::BoxError;

/// Object storage backed by a single S3 bucket.
///
/// Construct with [`S3ObjectStore::new`] (explicit client — tests, LocalStack,
/// custom endpoints) or [`S3ObjectStore::from_env`] (default AWS config chain).
#[derive(Clone)]
pub struct S3ObjectStore {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl std::fmt::Debug for S3ObjectStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3ObjectStore")
            .field("bucket", &self.bucket)
            .finish_non_exhaustive()
    }
}

/// Metadata for a stored object, returned by [`S3ObjectStore::head`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ObjectMeta {
    /// Size in bytes, if S3 reported it.
    pub content_length: Option<u64>,
    /// MIME type, if set when the object was stored.
    pub content_type: Option<String>,
    /// Entity tag (often the MD5 of the content), if present.
    pub e_tag: Option<String>,
}

impl S3ObjectStore {
    /// Bind a store to `bucket` using an explicit S3 client.
    ///
    /// Use this for tests, LocalStack, custom endpoints, or applications that
    /// already centralize AWS SDK setup.
    pub fn new(client: aws_sdk_s3::Client, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
        }
    }

    /// Bind a store to `bucket` using the default AWS SDK config chain
    /// (environment, config files, web identity, IMDS, ECS task role, …).
    pub async fn from_env(bucket: impl Into<String>) -> Self {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Self::new(aws_sdk_s3::Client::new(&config), bucket)
    }

    /// The bucket this store is bound to.
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Fetch an object fully into memory.
    ///
    /// Prefer [`Self::download_response`] for serving files to clients; this is
    /// for small objects (manifests, config) you need in memory.
    ///
    /// # Errors
    /// Returns an error if the object is missing or the request fails.
    pub async fn get(&self, key: &str) -> Result<Bytes, BoxError> {
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| format!("S3 get_object {}/{key} failed: {e}", self.bucket))?;
        let data = output
            .body
            .collect()
            .await
            .map_err(|e| format!("S3 read body {}/{key} failed: {e}", self.bucket))?;
        Ok(data.into_bytes())
    }

    /// Store an object, optionally setting its content type.
    ///
    /// # Errors
    /// Returns an error if the upload fails.
    pub async fn put(
        &self,
        key: &str,
        body: Bytes,
        content_type: Option<&str>,
    ) -> Result<(), BoxError> {
        let mut request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(body.into());
        if let Some(ct) = content_type {
            request = request.content_type(ct);
        }
        request
            .send()
            .await
            .map_err(|e| format!("S3 put_object {}/{key} failed: {e}", self.bucket))?;
        Ok(())
    }

    /// Fetch object metadata, or `None` if the object does not exist.
    ///
    /// # Errors
    /// Returns an error for failures other than "not found".
    pub async fn head(&self, key: &str) -> Result<Option<ObjectMeta>, BoxError> {
        let result = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await;
        match result {
            Ok(output) => Ok(Some(ObjectMeta {
                content_length: output.content_length().and_then(|n| u64::try_from(n).ok()),
                content_type: output.content_type().map(str::to_owned),
                e_tag: output.e_tag().map(str::to_owned),
            })),
            Err(error) => {
                if error
                    .as_service_error()
                    .is_some_and(aws_sdk_s3::operation::head_object::HeadObjectError::is_not_found)
                {
                    Ok(None)
                } else {
                    Err(format!("S3 head_object {}/{key} failed: {error}", self.bucket).into())
                }
            }
        }
    }

    /// List the keys under `prefix` (handles pagination).
    ///
    /// # Errors
    /// Returns an error if a list page request fails.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, BoxError> {
        let mut keys = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix);
            if let Some(token) = &continuation {
                request = request.continuation_token(token);
            }
            let output = request
                .send()
                .await
                .map_err(|e| format!("S3 list_objects_v2 {}/{prefix} failed: {e}", self.bucket))?;
            for object in output.contents() {
                if let Some(key) = object.key() {
                    keys.push(key.to_owned());
                }
            }
            if output.is_truncated().unwrap_or(false) {
                continuation = output.next_continuation_token().map(str::to_owned);
                if continuation.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(keys)
    }

    /// Create a presigned GET URL valid for `expires_in`.
    ///
    /// Useful for offloading large downloads directly to S3 instead of
    /// streaming through the service.
    ///
    /// # Errors
    /// Returns an error if the presign configuration or request build fails.
    pub async fn presigned_get(&self, key: &str, expires_in: Duration) -> Result<String, BoxError> {
        let presigning = aws_sdk_s3::presigning::PresigningConfig::expires_in(expires_in)
            .map_err(|e| format!("S3 presign config invalid: {e}"))?;
        let presigned = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(presigning)
            .await
            .map_err(|e| format!("S3 presign {}/{key} failed: {e}", self.bucket))?;
        Ok(presigned.uri().to_owned())
    }

    /// Stream an object to an HTTP client as a [`Response`].
    ///
    /// The body is streamed (not buffered), and `Content-Type` /
    /// `Content-Length` are set from the object's metadata. A missing object
    /// becomes `404 Not Found`; an upstream failure becomes `502 Bad Gateway`.
    /// This is the handler-friendly way to serve files from S3.
    pub async fn download_response(&self, key: &str) -> Response {
        let output = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => output,
            Err(error) => {
                if error
                    .as_service_error()
                    .is_some_and(aws_sdk_s3::operation::get_object::GetObjectError::is_no_such_key)
                {
                    return (StatusCode::NOT_FOUND, "not found").into_response();
                }
                tracing::warn!(bucket = %self.bucket, key, %error, "S3 download failed");
                return (StatusCode::BAD_GATEWAY, "upstream storage error").into_response();
            }
        };

        let content_type = output
            .content_type()
            .unwrap_or("application/octet-stream")
            .to_owned();
        let content_length = output.content_length();
        let stream = tokio_util::io::ReaderStream::new(output.body.into_async_read());

        let mut builder = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type);
        if let Some(len) = content_length {
            builder = builder.header(header::CONTENT_LENGTH, len);
        }
        match builder.body(Body::from_stream(stream)) {
            Ok(response) => response,
            Err(error) => {
                tracing::error!(%error, "failed to build S3 download response");
                (StatusCode::INTERNAL_SERVER_ERROR, "response build error").into_response()
            }
        }
    }
}
