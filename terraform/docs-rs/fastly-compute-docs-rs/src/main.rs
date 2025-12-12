mod shield;

use fastly::{
    Backend, ConfigStore, Error, Request, Response, SecretStore,
    erl::{ERL, Penaltybox, RateCounter, RateWindow},
    error::Context as _,
    http::{
        HeaderName, Method, StatusCode,
        header::{CACHE_CONTROL, EXPIRES, STRICT_TRANSPORT_SECURITY},
        request::SendErrorCause,
    },
};
use std::time::Duration;

// Should match the backend name in terraform
const DOCS_RS_BACKEND: &str = "docs_rs_origin";

// Should match the secret store name in terraform
const DOCS_RS_SECRET_STORE: &str = "docs_rs_secrets";
// Should match the secret item key in terraform
const ORIGIN_AUTH_KEY: &str = "origin-auth";

// Should match the dictionary name in terraform
const DOCS_RS_CONFIG: &str = "docs_rs_config";
const SHIELD_POP_KEY: &str = "shield_pop";
const HSTS_MAX_AGE_KEY: &str = "hsts_max_age";

const FASTLY_CLIENT_IP: HeaderName = HeaderName::from_static("fastly-client-ip");
const SURROGATE_CONTROL: HeaderName = HeaderName::from_static("surrogate-control");
const X_ORIGIN_AUTH: HeaderName = HeaderName::from_static("x-origin-auth");
const X_COMPRESS_HINT: HeaderName = HeaderName::from_static("x-compress-hint");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");

#[derive(thiserror::Error, Debug)]
#[error("rate limit exceeded")]
struct RateLimitExceeded;

#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    let config = ConfigStore::open(DOCS_RS_CONFIG);
    let shield = shield::Context::load(&config)?;

    let mut request_is_cacheable = req.is_cacheable();
    match req.get_method() {
        &Method::GET | &Method::HEAD | &Method::OPTIONS => {
            // for GET/HEAD/OPTIONS request, follow what the backend sends in the headers.
            // Don't apply any default when there are no headers.
            req.set_after_send(|response_candidate| {
                // By design, fastly caching happens _before_ the response ends up back in our code here.
                // (below, at `let mut response = req.send(backend)?`).
                //
                // In the case that the origin/backend doesnt contain any caching headers,
                // fastly will apply a default TTL.
                //
                // We don't want this.
                //
                // So we will check if the backend response has any caching header, and if it doesn't,
                // set the response to be uncacheable.
                //
                // If any backend wants anything to be cached, it has to set the appropriate caching
                // headers.
                //
                // Related docs:
                // https://www.fastly.com/documentation/guides/concepts/edge-state/cache/#controlling-cache-behavior-based-on-backend-response
                let has_any_cache_headers = [CACHE_CONTROL, SURROGATE_CONTROL, EXPIRES]
                    .iter()
                    .any(|header| response_candidate.contains_header(header));

                if !has_any_cache_headers {
                    response_candidate.set_uncacheable(
                        // don't record the "uncacheable" path.
                        // If set to `true`, fastly assumes the path will never be cacheable.
                        false,
                    );
                }
                Ok(())
            });
        }
        &Method::PUT | &Method::POST | &Method::PATCH | &Method::DELETE => {
            // Do not cache other methods
            req.set_pass(true);
            request_is_cacheable = false;
        }
        _ => {
            return Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED));
        }
    }

    if shield.target_is_origin() {
        let secrets = SecretStore::open(DOCS_RS_SECRET_STORE).expect("failed to open secret store");
        let origin_auth = secrets
            .get(ORIGIN_AUTH_KEY)
            .expect("failed to get origin auth from secret store")
            .plaintext();

        req.set_header(X_ORIGIN_AUTH, origin_auth.as_ref());
    }

    if req.get_header(X_FORWARDED_HOST).is_none() {
        // When the request doesn't have an X-Forwarded-Host header,
        // set one.
        // When this is a request on a shield POP, we should already
        // get the header from the edge POP, so just pass it on.
        // The forwarded host (= subdomain) will be needed
        req.set_header(
            X_FORWARDED_HOST,
            req.get_url()
                .host_str()
                .context("missing hostname in request URL")?
                .to_owned(),
        );
    }

    if req.get_header(FASTLY_CLIENT_IP).is_none() {
        // When the request doesn't have an Fastly-Client-Ip header, set one.
        // When this is a request on a shield POP, we should already
        // get the header from the edge POP, and just pass it on.
        //
        // https://www.fastly.com/documentation/reference/http/http-headers/Fastly-Client-IP/
        // We intentionally choose this simple header instead of X-Forwarded-For, because we only
        // need the client IP, and not all in between.
        req.set_header(
            FASTLY_CLIENT_IP,
            req.get_client_ip_addr()
                .context("this is the client request, it should have an IP address")?
                .to_string(),
        );
    }

    // Open the rate counter and penalty box.
    let rc = RateCounter::open("rc");
    // TODO: is there value in having an additional penalty box check at the start of the handler?
    let pb = Penaltybox::open("pb");
    // Open the Edge Rate Limiter based on the rate counter and penalty box.
    let limiter = ERL::open(rc, pb);

    if target_is_origin {
        // The client to rate limit.
        // FIXME: if IPv6 → normalize to /64
        let client_id = req.get_client_ip_addr().unwrap().to_string();
        if !request_is_cacheable {
            let result = limiter.check_rate(
                &client_id,
                1,
                RateWindow::SixtySecs,
                100,
                Duration::from_secs(15 * 60),
            );

            let is_blocked: bool = match result {
                Ok(is_blocked) => is_blocked,
                Err(err) => {
                    eprintln!("Failed to check the rate: {:?}", err);
                    false
                }
            };
            if is_blocked {
                return Ok(Response::from_status(StatusCode::TOO_MANY_REQUESTS)
                    .with_body_text_plain(
                        "You have sent too many requests recently. Try again later.",
                    ));

                // resp.set_header(header::RETRY_AFTER, ttl_secs.to_string());
                // resp.set_header("X-RateLimit-Limit", LIMIT.to_string());
                // resp.set_header("X-RateLimit-Remaining", remaining.to_string());
                // resp.set_header("X-RateLimit-Reset", window_end.to_string());
            }
        } else {
            req.set_before_send(move |_req| {
                let result = limiter.check_rate(
                    &client_id,
                    1,
                    RateWindow::SixtySecs,
                    100,
                    Duration::from_secs(15 * 60),
                );

                let is_blocked: bool = match result {
                    Ok(is_blocked) => is_blocked,
                    Err(err) => {
                        eprintln!("Failed to check the rate: {:?}", err);
                        false
                    }
                };
                if is_blocked {
                    Err(SendErrorCause::Custom(RateLimitExceeded.into()))
                } else {
                    Ok(())
                }
            });
        }
    }

    // Send request to backend, shield POP or origin
    let mut resp = match req.send(shield.target_backend()) {
        Ok(resp) => resp,
        Err(err) => {
            if let SendErrorCause::Custom(custom) = err.root_cause() {
                // FIXME: this needs testing.
                if custom.is::<RateLimitExceeded>() {
                    return Ok(Response::from_status(StatusCode::TOO_MANY_REQUESTS)
                        .with_body_text_plain(
                            "You have sent too many requests recently. Try again later.",
                        ));
                    // resp.set_header(header::RETRY_AFTER, ttl_secs.to_string());
                    // resp.set_header("X-RateLimit-Limit", LIMIT.to_string());
                    // resp.set_header("X-RateLimit-Remaining", remaining.to_string());
                    // resp.set_header("X-RateLimit-Reset", window_end.to_string());
                }
            }
            return Err(err.into());
        }
    };

    // set HSTS header
    if shield.response_is_for_client() {
        let ttl: u32 = config
            .get(HSTS_MAX_AGE_KEY)
            .and_then(|ttl| ttl.parse().ok())
            .unwrap_or(31_557_600);

        resp.set_header(STRICT_TRANSPORT_SECURITY, format!("max-age={ttl}"));
    }

    // enable dynamic compression at the edge
    // https://www.fastly.com/documentation/guides/concepts/compression/#dynamic-compression
    //
    // We always set this header, assuming it can also help optimizing the transfer between
    // the edge & shield POPs.
    resp.set_header(X_COMPRESS_HINT, "on");

    // perhaps?
    // resp.set_header("X-RateLimit-Limit", LIMIT.to_string());
    // resp.set_header("X-RateLimit-Remaining", remaining.to_string());
    // resp.set_header("X-RateLimit-Reset", window_end.to_string());
    Ok(resp)
}
