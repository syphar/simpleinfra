use fastly::{
    Request,
    erl::{ERL, Penaltybox, RateCounter, RateWindow},
};
use std::{net::IpAddr, time::Duration};

use crate::FASTLY_CLIENT_IP;

const RATE_COUNTER: &str = "rc";
const PENALTY_BOX: &str = "pb";

const MAX_RPS_SUSTAINED: u32 = 10;
const MAX_BURST: u32 = 60;
const PENALTY_TTL: Duration = Duration::from_secs(15 * 60);

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

    fn check_rates(&self) -> bool {
        let burst_rate = self
            .rate_counter
            .lookup_rate(&self.key, RateWindow::OneSec)
            .unwrap();
        if burst_rate > MAX_BURST {
            eprintln!(
                "client \"{}\" exceeded burst rate exceeded: {} rps",
                self.key, burst_rate
            );
            self.penalty_box.add(&self.key, PENALTY_TTL).unwrap();
            return true;
        }

        let sustained_rate = self
            .rate_counter
            .lookup_rate(&self.key, RateWindow::TenSecs)
            .unwrap();

        if sustained_rate > MAX_RPS_SUSTAINED {
            eprintln!(
                "client \"{}\" exceeded sustained rate exceeded: {} rps",
                self.key, burst_rate
            );
            self.penalty_box.add(&self.key, PENALTY_TTL).unwrap();
            return true;
        }

        false
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

    /// count a request
    pub fn inc(&self) {
        if let Err(err) = self.rate_counter.increment(&self.key, 1) {
            eprintln!("Failed to increment rate counter: {:?}", err);
        }
        self.check_rates();
    }
}

fn key_from_request<'a>(fastly_client_ip_header: Option<&str>, client_ip: IpAddr) -> String {
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

    const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(
        // 2003:fb:ef0e:800:5172:1949:a0e0:9340
        8195, 251, 61198, 2048, 20850, 6473, 41184, 37696,
    ));

    #[test]
    fn test_invalid_header_value_falls_back_to_client_ip() {
        assert_eq!(key_from_request(Some("asdf"), V4), V4.to_string());
    }

    #[test]
    fn test_v4_from_header() {
        let key = key_from_request(Some(V4.to_string()).as_deref(), V6);
        assert_eq!(key, V4.to_string());
        assert_eq!(key, "192.168.1.1");
    }

    #[test]
    fn test_v6_from_header() {
        let key = key_from_request(Some(V6.to_string()).as_deref(), V4);
        assert_eq!(key, "2003:fb:ef0e:800::/64");
    }

    #[test]
    fn test_v4_from_client() {
        let key = key_from_request(None, V4);
        assert_eq!(key, V4.to_string());
        assert_eq!(key, "192.168.1.1");
    }

    #[test]
    fn test_v6_from_client() {
        let key = key_from_request(None, V6);
        assert_eq!(key, "2003:fb:ef0e:800::/64");
    }
}

// if shield.target_is_origin() {
//     // The client to rate limit.
//     // FIXME: if IPv6 → normalize to /64
//     let client_id = req.get_client_ip_addr().unwrap().to_string();
//     if !request_is_cacheable {
//         let result = limiter.check_rate(
//             &client_id,
//             1,
//             RateWindow::SixtySecs,
//             100,
//             Duration::from_secs(15 * 60),
//         );

//         let is_blocked: bool = match result {
//             Ok(is_blocked) => is_blocked,
//             Err(err) => {
//                 eprintln!("Failed to check the rate: {:?}", err);
//                 false
//             }
//         };
//         if is_blocked {
//             return Ok(Response::from_status(StatusCode::TOO_MANY_REQUESTS)
//                 .with_body_text_plain(
//                     "You have sent too many requests recently. Try again later.",
//                 ));

//             // resp.set_header(header::RETRY_AFTER, ttl_secs.to_string());
//             // resp.set_header("X-RateLimit-Limit", LIMIT.to_string());
//             // resp.set_header("X-RateLimit-Remaining", remaining.to_string());
//             // resp.set_header("X-RateLimit-Reset", window_end.to_string());
//         }
//     } else {
//         req.set_before_send(move |_req| {
//             // this callback is called
//             // - after a cache miss, but
//             // - before sending the request to the backend
//             //
//             // So the perfect time to rate-limit, if needed.
//             let result = limiter.check_rate(
//                 &client_id,
//                 1,
//                 RateWindow::SixtySecs,
//                 100,
//                 Duration::from_secs(15 * 60),
//             );

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
