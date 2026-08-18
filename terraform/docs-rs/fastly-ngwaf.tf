# Next-Gen WAF workspace
resource "fastly_ngwaf_workspace" "webapp" {
  name        = "${local.domain_name}-waf"
  description = "Next-Gen WAF workspace for ${local.domain_name}"

  mode = "block"

  # Configure when the WAF should flag an IP address as potentially malicious based on cumulative attack signals over different time windows.
  #
  # Fastly's Next-Gen WAF analyzes each request and assigns attack signals when it detects suspicious patterns
  # (SQL injection attempts, XSS, path traversal, etc.). These signals accumulate per IP address over time.
  attack_signal_thresholds {
    # If an IP accumulates 100+ attack signals within 1 minute, it's flagged as an attacker
    one_minute = 100
    # If an IP accumulates 500+ attack signals within 10 minutes, it's flagged
    ten_minutes = 500
    # If an IP accumulates 1000+ attack signals within 1 hour, it's flagged
    one_hour = 1000
    # If true, a single attack signal immediately blocks the IP.
    # We set it to false, to allow for legitimate edge cases
    immediate = false
  }
}

# Custom signal used for per-client rate limiting in the webapp workspace.
resource "fastly_ngwaf_workspace_signal" "webapp_rate_limit" {
  workspace_id = fastly_ngwaf_workspace.webapp.id
  name         = "webapp-rate-limit"
  description  = "webapp per-IP rate limiting"
}

# Keep the rate limit aligned with the previous nginx configuration:
# https://github.com/rust-lang/docs.rs/issues/2779
# https://blog.nginx.org/blog/rate-limiting-nginx
#
# The one-minute window maintains the sustained rate of one request per second,
# while allowing docs.rs pages to load their 20-30 assets in a burst when uncached.
resource "fastly_ngwaf_workspace_rule" "webapp_per_ip_rate_limit" {
  workspace_id = fastly_ngwaf_workspace.webapp.id
  type         = "rate_limit"
  description  = "Rate limit per client IP to 60 requests per minute"
  enabled      = true

  # Fastly NGWAF requires at least one rule condition.
  # Match all request paths so the rate limit applies globally.
  group_operator = "all"
  condition {
    field    = "path"
    operator = "contains"
    value    = "/"
  }

  action {
    signal        = "site.webapp-rate-limit"
    type          = "block_signal"
    response_code = 429
  }

  rate_limit {
    signal    = fastly_ngwaf_workspace_signal.webapp_rate_limit.reference_id
    threshold = 60
    interval  = 60
    duration  = 60

    client_identifiers {
      type = "ip"
    }
  }
}
