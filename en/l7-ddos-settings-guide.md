## Security > DDoS Guard > L7 DDoS Security Configuration Guide

This guide describes security configuration methods to effectively mitigate L7 DDoS attacks.

## Nginx

| Number | Item | How to configure | Content | Priority | Example |
| --- | --- | --- | ---- | ---- | ---- |
| 1 | Request rate limit | Set limit_req_zone / limit_req | Prevent excessive HTTP requests by limiting the number of requests per second by IP | Required | http {<BR>  limit_req_zone $binary_remote_addr zone=req_limit_per_ip:10m rate=5r/s;<BR>}server {<BR>  limit_req zone=req_limit_per_ip burst=10 nodelay;<BR>} |
| 2 | Connection limit | Set limit_conn_zone / limit_conn | Limit the number of simultaneous connections from a single IP | Required | http {<BR>  limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;<BR>}server {<BR>  limit_conn conn_limit_per_ip 10;<BR>} |
| 3 | Request body size limit | Set client_max_body_size | Prevent resource exhaustion due to large POST requests | Required | client_max_body_size 1m; |
| 4 | Buffer size limit | Set client_body_buffer_size and client_header_buffer_size | Limit request header and body buffer usage (Slowloris attack defense) | Required | client_body_buffer_size 16k;<BR>client_header_buffer_size 1k; |
| 5 | Keep-Alive limit | Set keepalive_timeout | Limit client session occupancy time | Required | keepalive_timeout 10s; |
| 6 | Request wait time limit | Set client_header_timeout and send_timeout | Prevent slow request (Slow HTTP) attacks | Required | client_header_timeout 10s;<BR>send_timeout 10s; |
| 7 | Restrict HTTP methods | Restrict only allowed methods with if statements | Block requests for unnecessary methods (TRACE, PUT, etc.) | Recommended | if ($request_method !~ ^(GET\|POST\|HEAD)$) { return 444; } |
| 8 | Block abnormal user agents | Filter user agents with regular expressions | Block access from automated tools such as scanners, bots, and curl | Recommended | if ($http_user_agent ~* (masscan\|curl\|python\|nmap)) { return 403; } |
| 9 | Status monitoring | Set stub_status | Check the number of requests/sessions in real time (for operational maintenance) | Recommended | location /nginx_status {<BR>  stub_status;<BR>  allow 127.0.0.1;<BR>  deny all;<BR>} |
| 10 | Caching settings | Proxy cache settings | Reducing backend load by caching identical requests | Recommendation | proxy_cache_path /tmp/nginx_cache levels=1:2 keys_zone=my_cache:10m;<BR>location / {<BR>  proxy_cache my_cache;<BR>  proxy_cache_use_stale error timeout updating;<BR>} |

## Apache

| Number | Item | How to configure | Content | Priority | Example |
| --- | --- | --- | ---- | ---- | ---- |
| 1 | Configuring mod_evasive | After installing mod_evasive with yum, configure /etc/httpd/conf.d/mod_evasive.conf | Automatically block IP addresses that make multiple requests within a short period of time | Required | DOSPageCount 2<BR>DOSSiteCount 50<BR>DOSBlockingPeriod 10 |
| 2 | mod_qos settings | yum install mod_qos and then /etc/httpd/conf.d/mod_qos.conf | Maximum connections and requests per IP | Required | QS_SrvMaxConnPerIP 10<BR>QS_SrvMaxConnClose 20<BR>QS_SrvRequestRate 5 |
| 3 | KeepAlive limit | KeepAliveTimeout setting | Prevent long-term connection keeping | Required | KeepAlive On<BR>MaxKeepAliveRequests 100<BR>KeepAliveTimeout 5 |
| 4 | Request body size limit | Set LimitRequestBody | Limit large POST requests | Required | LimitRequestBody 1048576 |
| 5 | Adjust Timeout | Set Timeout and RequestReadTimeout | Block slow requests/responses | Required | Timeout 10<BR>RequestReadTimeout header=10-20,MinRate=500 |
| 6 | HTTP Method Restrictions | Use <LimitExcept\> block | Allow only allowed methods | Required | <LimitExcept GET POST HEAD\><BR>  Deny from all<BR></LimitExcept\> |
| 7 | User-Agent Filtering | SetEnvIfNoCase + Deny | Blocking Abnormal User-Agents | Recommendation | SetEnvIfNoCase User-Agent "curl" bad_bot<BR>Order Allow,Deny<BR>Allow from all<BR>Deny from env=bad_bot |
| 8 | Request rate limit (mod_ratelimit) | Using mod_ratelimit | Limiting response rates to prevent excessive requests | Recommended | SetOutputFilter RATE_LIMIT<BR>SetEnv rate-limit 400 |
| 9 | Enhanced log format | Modified LogFormat | Enhanced traceability, including request and response sizes and User-Agent | Recommended | LogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\"" combined |

## Load Balancer

| Number | Item | How to configure | Content | Example |
| --- | --- | --- | ---- | ---- |
| 1 | Session Connection Limit | Connection Limit Setting | Specifies the number of TCP sessions the listener will maintain concurrently | Default: 60,000<BR>Step-by-step adjustments are required depending on the service characteristics |
| 2 | Keep-Alive limit | Keep-Alive timeout setting | Specify the session maintenance time between the client and server in seconds | Default: 300 seconds |
| 3 | Automatically block abnormal requests | Block invalid requests | Block HTTP request headers containing invalid characters | Default: enable |
