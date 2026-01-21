## Security > DDoS Guard > L7 DDoSセキュリティ設定ガイド

ここではL7 DDoS攻撃に効果的に対応するためのセキュリティ設定方法について説明します。

## Nginx

| 番号 | 項目 | 設定方法 | 内容 | 優先順位 | 例 |
| --- | --- | --- | ---- | ---- | ---- |
| 1 | リクエスト速度制限(Rate Limit) | limit_req_zone / limit_req設定 | IPごとの1秒あたりのリクエスト数制限により過度なHTTPリクエストを防御 | 必須 | http {<BR>  limit_req_zone $binary_remote_addr zone=req_limit_per_ip:10m rate=5r/s;<BR>}server {<BR>  limit_req zone=req_limit_per_ip burst=10 nodelay;<BR>} |
| 2 | 同時接続制限(Connection Limit) | limit_conn_zone / limit_conn設定 | 1つのIPから同時に確立できる接続数を制限 | 必須 | http {<BR>  limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;<BR>}server {<BR>  limit_conn conn_limit_per_ip 10;<BR>} |
| 3 | リクエスト本文サイズ制限 | client_max_body_size設定 | 大容量POSTリクエストによるリソース枯渇を防止 | 必須 | client_max_body_size 1m; |
| 4 | バッファサイズ制限 | client_body_buffer_size, client_header_buffer_size設定 | リクエストヘッダ・本文のバッファ使用量制限(Slowloris攻撃防御) | 必須 | client_body_buffer_size 16k;<BR>client_header_buffer_size 1k; |
| 5 | Keep-Alive制限 | keepalive_timeout設定 | クライアントのセッション占有時間を制限 | 必須 | keepalive_timeout 10s; |
| 6 | リクエスト待機時間制限 | client_header_timeout, send_timeout設定 | 遅いリクエスト(Slow HTTP)攻撃を防御 | 必須 | client_header_timeout 10s;<BR>send_timeout 10s; |
| 7 | HTTP Method制限 | if文で許可されたメソッドのみ制限 | 不要なメソッド(TRACE、PUTなど)のリクエストをブロック | 推奨 | if ($request_method !~ ^(GET\|POST\|HEAD)$) { return 444; } |
| 8 | 異常なUser-Agentブロック | 正規表現でUser-Agentフィルタリング | スキャナー、Bot、curlなど自動化ツールからのアクセスをブロック | 推奨 | if ($http_user_agent ~* (masscan\|curl\|python\|nmap)) { return 403; } |
| 9 | ステータスモニタリング | stub_status設定 | リアルタイムリクエスト/セッション数確認(運営点検用) | 推奨 | location /nginx_status {<BR>  stub_status;<BR>  allow 127.0.0.1;<BR>  deny all;<BR>} |
| 10 | キャッシュ設定 | proxy_cache設定 | 同一リクエストのキャッシュでバックエンド負荷を軽減 | 推奨 | proxy_cache_path /tmp/nginx_cache levels=1:2 keys_zone=my_cache:10m;<BR>location / {<BR>  proxy_cache my_cache;<BR>  proxy_cache_use_stale error timeout updating;<BR>} |

## Apache

| 番号 | 項目 | 設定方法 | 内容 | 優先順位 | 例 |
| --- | --- | --- | ---- | ---- | ---- |
| 1 | mod_evasive設定 | yum install mod_evasive実行後、/etc/httpd/conf.d/mod_evasive.confを設定 | 短時間内の多数リクエストIPを自動ブロック | 必須 | DOSPageCount 2<BR>DOSSiteCount 50<BR>DOSBlockingPeriod 10 |
| 2 | mod_qos設定 | yum install mod_qos実行後、/etc/httpd/conf.d/mod_qos.confを設定 | IPごとの最大接続数及びリクエスト数を制限 | 必須 | QS_SrvMaxConnPerIP 10<BR>QS_SrvMaxConnClose 20<BR>QS_SrvRequestRate 5 |
| 3 | KeepAlive制限 | KeepAliveTimeout設定 | 長時間の接続維持を防止 | 必須 | KeepAlive On<BR>MaxKeepAliveRequests 100<BR>KeepAliveTimeout 5 |
| 4 | リクエスト本文サイズ制限 | LimitRequestBody設定 | 大容量POSTリクエストを制限 | 必須 | LimitRequestBody 1048576 |
| 5 | Timeout調整 | Timeout, RequestReadTimeout設定 | 遅いリクエスト/レスポンスをブロック | 必須 | Timeout 10<BR>RequestReadTimeout header=10-20,MinRate=500 |
| 6 | HTTP Method制限 | <LimitExcept\>ブロック使用 | 許可されたメソッドのみ許可 | 必須 | <LimitExcept GET POST HEAD\><BR>  Deny from all<BR></LimitExcept\> |
| 7 | User-Agentフィルタリング | SetEnvIfNoCase + Deny | 異常なUser-Agentブロック | 推奨 | SetEnvIfNoCase User-Agent "curl" bad_bot<BR>Order Allow,Deny<BR>Allow from all<BR>Deny from env=bad_bot |
| 8 | リクエスト速度制限(mod_ratelimit) | mod_ratelimit使用 | レスポンス転送速度制限により過度なリクエストを抑制 | 推奨 | SetOutputFilter RATE_LIMIT<BR>SetEnv rate-limit 400 |
| 9 | ログフォーマット強化 | LogFormat修正 | リクエスト、レスポンスサイズ、User-Agentを含めて追跡性を強化 | 推奨 | LogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\"" combined |

## Load Balancer

| 番号 | 項目 | 設定方法 | 内容 | 例 |
| --- | --- | --- | ---- | ---- |
| 1 | セッション接続制限 | 接続制限設定 | リスナーが同時に維持するTCPセッション数を指定 | デフォルト値: 60,000<BR>サービス特性に応じた段階的な調整が必要 |
| 2 | Keep-Alive制限 | Keep-Aliveタイムアウト設定 | クライアント及びサーバーとのセッション維持時間を秒単位で指定 | デフォルト値: 300秒 |
| 3 | 異常なリクエスト自動ブロック | 無効なリクエストブロック設定 | HTTPリクエストヘッダに無効な文字が含まれる場合にブロック | デフォルト値: 使用 |
