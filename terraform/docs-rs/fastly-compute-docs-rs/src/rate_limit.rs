use fastly::{
    Request,
    erl::{Penaltybox, RateCounter, RateWindow},
    http::request::SendErrorCause,
};
use std::{net::IpAddr, time::Duration};

use crate::FASTLY_CLIENT_IP;

const RATE_COUNTER: &str = "rc";
const PENALTY_BOX: &str = "pb";

const MAX_RPS_SUSTAINED: u32 = 10;
const MAX_BURST: u32 = 60;

// TTL constraints: 1m..1h, truncated to nearest minute;
// effective minimum can behave like ~2 minutes in practice.  [oai_citation:1‡fastly.com](https://www.fastly.com/documentation/guides/compute/edge-data-storage/working-with-kv-stores/?utm_source=chatgpt.com)
const PENALTY_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(thiserror::Error, Debug)]
#[error("rate limit exceeded")]
pub(crate) struct RateLimitExceeded;

#[derive(Debug)]
pub(crate) enum RateLimitResponse {
    Blocked,
    Allowed,
}

impl From<bool> for RateLimitResponse {
    fn from(is_blocked: bool) -> Self {
        if is_blocked {
            RateLimitResponse::Blocked
        } else {
            RateLimitResponse::Allowed
        }
    }
}

impl RateLimitResponse {
    pub(crate) fn is_blocked(&self) -> bool {
        matches!(self, RateLimitResponse::Blocked)
    }
}

pub(crate) struct RateLimiter {
    key: String,
    rate_counter: RateCounter,
    penalty_box: Penaltybox,
}

impl RateLimiter {
    pub fn from_request(req: &Request) -> Self {
        Self {
            key: key_from_request(
                req.get_header_str(FASTLY_CLIENT_IP),
                req.get_client_ip_addr()
                    .expect("client IP missing. Can only happen if this is not the client request"),
            ),
            rate_counter: RateCounter::open(RATE_COUNTER),
            penalty_box: Penaltybox::open(PENALTY_BOX),
        }
    }

    fn add_to_penalty_box(&self) {
        println!(
            "adding \"{}\" to penalty box because of too many request",
            self.key
        );
        if let Err(err) = self.penalty_box.add(&self.key, PENALTY_TTL) {
            eprintln!("Failed to add \"{}\", to penalty box: {:?}", self.key, err);
        }
    }

    fn lookup_rate(&self, window: RateWindow) -> u32 {
        match self.rate_counter.lookup_rate(&self.key, window) {
            Ok(rate) => rate,
            Err(err) => {
                eprintln!("Failed to lookup rate for \"{}\": {:?}", self.key, err);
                0 // on error, return 0 rate, so we don't rate-limit
            }
        }
    }

    fn check_rates(&self) -> RateLimitResponse {
        let burst_rate = self.lookup_rate(RateWindow::OneSec);
        if burst_rate > MAX_BURST {
            eprintln!(
                "client \"{}\" exceeded burst rate exceeded: {} rps",
                self.key, burst_rate
            );
            self.add_to_penalty_box();
            return RateLimitResponse::Blocked;
        }

        let sustained_rate = self.lookup_rate(RateWindow::TenSecs);
        if sustained_rate > MAX_RPS_SUSTAINED {
            eprintln!(
                "client \"{}\" exceeded sustained rate exceeded: {} rps",
                self.key, burst_rate
            );
            self.add_to_penalty_box();
            return RateLimitResponse::Blocked;
        }

        RateLimitResponse::Allowed
    }

    pub fn is_blocked(&self) -> bool {
        match self.penalty_box.has(&self.key) {
            Ok(blocked) => blocked,
            Err(err) => {
                eprintln!("Failed to check penalty box: {:?}", err);
                false
            }
        }
    }

    /// count a request, returns if the rate limit is reached
    /// after the count.
    pub fn increment(&self) -> RateLimitResponse {
        if let Err(err) = self.rate_counter.increment(&self.key, 1) {
            eprintln!("Failed to increment rate counter: {:?}", err);
        }
        self.check_rates()
    }

    /// callable that should be registered on the request to the backend.
    pub fn request_before_send(&self, _req: &mut Request) -> Result<(), SendErrorCause> {
        // this callback is called when the request
        // 1. is cacheable
        // 2. a cache miss happens
        // 3. before the request is sent to the backend.
        if self.increment().is_blocked() {
            Err(SendErrorCause::Custom(RateLimitExceeded.into()))
        } else {
            Ok(())
        }
    }
}

fn key_from_request(fastly_client_ip_header: Option<&str>, client_ip: IpAddr) -> String {
    let client_ip = fastly_client_ip_header
        .and_then(|value| value.parse::<IpAddr>().ok())
        .unwrap_or(client_ip);

    match client_ip {
        IpAddr::V4(addr) => addr.to_string(),
        IpAddr::V6(addr) => {
            // Keep first 4 segments (64 bits), zero the rest
            let se = addr.segments();
            let prefix64 = std::net::Ipv6Addr::new(se[0], se[1], se[2], se[3], 0, 0, 0, 0);
            format!("{}/64", prefix64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use test_case::{test_case, test_matrix};

    const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(
        // 2003:fb:ef0e:800:5172:1949:a0e0:9340
        8195, 251, 61198, 2048, 20850, 6473, 41184, 37696,
    ));
    const FALLBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 10, 1, 1));

    #[test_matrix(
        [Some("asdf"), Some(""), None],
        [V4, V6]
    )]
    fn test_invalid_or_empty_header_falls_back_to_client_ip(
        header_value: Option<&str>,
        fallback: IpAddr,
    ) {
        // the resulting key is the same, no matter if the IP came via header value
        // or via client-ip fallback.
        assert_eq!(
            key_from_request(header_value, fallback),
            key_from_request(Some(fallback.to_string()).as_deref(), FALLBACK),
        );
    }

    #[test_case(&V4.to_string() => "192.168.1.1")]
    #[test_case(&V6.to_string() => "2003:fb:ef0e:800::/64")]
    fn test_read_from_header(header_value: &str) -> String {
        // header value wins over client-ip fallback.
        key_from_request(Some(header_value), FALLBACK)
    }
}

//             let is_blocked: bool = match result {
//                 Ok(is_blocked) => is_blocked,
//                 Err(err) => {
//                     eprintln!("Failed to check the rate: {:?}", err);
//                     false
//                 }
//             };
//             if is_blocked {
//                 Err(SendErrorCause::Custom(RateLimitExceeded.into()))
//             } else {
//                 Ok(())
//             }
//         });
//     }
// }
//
// // Send request to backend, shield POP or origin
// let mut resp = match req.send(shield.target_backend()) {
//     Ok(resp) => resp,
//     Err(err) => {
//         if let SendErrorCause::Custom(custom) = err.root_cause() {
//             // FIXME: this needs testing.
//             if custom.is::<RateLimitExceeded>() {
//                 return Ok(Response::from_status(StatusCode::TOO_MANY_REQUESTS)
//                     .with_body_text_plain(
//                         "You have sent too many requests recently. Try again later.",
//                     ));
//                 // resp.set_header(header::RETRY_AFTER, ttl_secs.to_string());
//                 // resp.set_header("X-RateLimit-Limit", LIMIT.to_string());
//                 // resp.set_header("X-RateLimit-Remaining", remaining.to_string());
//                 // resp.set_header("X-RateLimit-Reset", window_end.to_string());
//             }
//         }
//         return Err(err.into());
//     }
// };
// perhaps?
// resp.set_header("X-RateLimit-Limit", LIMIT.to_string());
// resp.set_header("X-RateLimit-Remaining", remaining.to_string());
// resp.set_header("X-RateLimit-Reset", window_end.to_string());
