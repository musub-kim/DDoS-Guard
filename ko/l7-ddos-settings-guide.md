## Security > DDoS Guard > L7 DDoS 보안 설정 가이드

여기에서는 L7 DDoS 공격을 효과적으로 대응하기 위한 보안 설정 방법을 설명합니다.

## Nginx

| 번호 | 항목 | 설정 방법 | 내용 | 우선 순위 | 예시 |
| --- | --- | --- | ---- | ---- | ---- |
| 1 | 요청 속도 제한 (Rate Limit) | limit_req_zone / limit_req 설정 | IP별 초당 요청 수 제한으로 과도한 HTTP 요청 방어 | 필수 | http {<BR>   limit_req_zone $binary_remote_addr zone=req_limit_per_ip:10m rate=5r/s; <BR>} server {<BR>   limit_req zone=req_limit_per_ip burst=10 nodelay; <BR>} |
| 2 | 동시 연결 제한 (Connection Limit) | limit_conn_zone / limit_conn 설정 | 하나의 IP에서 동시에 맺을 수 있는 연결 수 제한 | 필수 | http {<BR>   limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m; <BR>} server {<BR>   limit_conn conn_limit_per_ip 10; <BR>} |
| 3 | 요청 본문 크기 제한 | client_max_body_size 설정 | 대용량 POST 요청으로 인한 리소스 고갈 방지 | 필수 | client_max_body_size 1m; |
| 4 | 버퍼 크기 제한 | client_body_buffer_size, client_header_buffer_size 설정 | 요청 헤더·본문 버퍼 사용량 제한 (Slowloris 방어) | 필수 | client_body_buffer_size 16k; <BR>client_header_buffer_size 1k; |
| 5 | Keep-Alive 제한 | keepalive_timeout 설정 | 클라이언트의 세션 점유 시간 제한 | 필수 | keepalive_timeout 10s; |
| 6 | 요청 대기 시간 제한 | client_header_timeout, send_timeout 설정 | 느린 요청(Slow HTTP) 공격 방어 | 필수 | client_header_timeout 10s; <BR>send_timeout 10s; |
| 7 | HTTP Method 제한 | if문으로 허용된 메서드만 제한 | 불필요한 메서드(TRACE, PUT 등) 요청 차단 | 권고 | if ($request_method !~ ^(GET\|POST\|HEAD)$) { return 444; } |
| 8 | 비정상 User-Agent 차단 | 정규식으로 User-Agent 필터링 | 스캐너, 봇, curl 등 자동화 툴 접근 차단 | 권고 | if ($http_user_agent ~* (masscan\|curl\|python\|nmap)) { return 403; } |
| 9 | 상태 모니터링 | stub_status 설정 | 실시간 요청/세션 수 확인 (운영 점검용) | 권고 | location /nginx_status {<BR>   stub_status;<BR>   allow 127.0.0.1;<BR>   deny all; <BR>} |
| 10 | 캐싱 설정 | proxy_cache 설정 | 동일 요청 캐싱으로 백엔드 부하 감소 | 권고 | proxy_cache_path /tmp/nginx_cache levels=1:2 keys_zone=my_cache:10m; <BR>location / {<BR>   proxy_cache my_cache;<BR>   proxy_cache_use_stale error timeout updating; <BR>} |

## Apache

| 번호 | 항목 | 설정 방법 | 내용 | 우선 순위 | 예시 |
| --- | --- | --- | ---- | ---- | ---- |
| 1 | mod_evasive 설정 | yum install mod_evasive 후 /etc/httpd/conf.d/mod_evasive.conf 설정 | 짧은 시간 내 다수 요청 IP 자동 차단 | 필수 | DOSPageCount 2 <BR>DOSSiteCount 50 <BR>DOSBlockingPeriod 10 |
| 2 | mod_qos 설정 | yum install mod_qos 후 /etc/httpd/conf.d/mod_qos.conf | IP별 최대 연결 수 및 요청 수 제한 | 필수 | QS_SrvMaxConnPerIP 10 <BR>QS_SrvMaxConnClose 20 <BR>QS_SrvRequestRate 5 |
| 3 | KeepAlive 제한 | KeepAliveTimeout 설정 | 장시간 연결 유지 방지 | 필수 | KeepAlive On <BR>MaxKeepAliveRequests 100 <BR>KeepAliveTimeout 5 |
| 4 | 요청 본문 크기 제한 | LimitRequestBody 설정 | 대용량 POST 요청 제한 | 필수 | LimitRequestBody 1048576 |
| 5 | Timeout 조정 | Timeout, RequestReadTimeout 설정 | 느린 요청/응답 차단 | 필수 | Timeout 10 <BR>RequestReadTimeout header=10-20,MinRate=500 |
| 6 | HTTP Method 제한 | <LimitExcept\> 블록 사용 | 허용된 메서드만 허용 | 필수 | <LimitExcept GET POST HEAD\><BR>   Deny from all <BR></LimitExcept\> |
| 7 | User-Agent 필터링 | SetEnvIfNoCase + Deny | 비정상 User-Agent 차단 | 권고 | SetEnvIfNoCase User-Agent "curl" bad_bot <BR>Order Allow,Deny <BR>Allow from all <BR>Deny from env=bad_bot |
| 8 | 요청 속도 제한 (mod_ratelimit) | mod_ratelimit 사용 | 응답 전송 속도 제한으로 과도한 요청 억제 | 권고 | SetOutputFilter RATE_LIMIT <BR>SetEnv rate-limit 400 |
| 9 | 로그 포맷 강화 | LogFormat 수정 | 요청, 응답 크기, User-Agent 포함해 추적성 강화 | 권고 | LogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\"" combined |

## Load Balancer

| 번호 | 항목 | 설정 방법 | 내용 | 예시 |
| --- | --- | --- | ---- | ---- |
| 1 | 세션 연결 제한 | 연결 제한 설정 | 리스너가 동시에 유지할 TCP 세션의 수를 지정 | 기본값 : 60,000 <BR>서비스 특성에 따라 단계적 조정 필요 |
| 2 | Keep-Alive 제한 | Keep-Alive 타임아웃 설정 | 클라이언트 및 서버와의 세션 유지 시간을 초 단위로 지정 | 기본값 : 300초 |
| 3 | 비정상 요청 자동 차단 | 유효하지 않은 요청 차단 설정 | HTTP 요청 헤더에 유효하지 않은 문자가 포함된 경우 차단 | 기본값 : 사용 |
