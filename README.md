xiao_scanning 漏洞扫描器
xiao_scanning 是一个用于扫描Web应用程序安全漏洞的工具，能够检测HTTP响应头和请求方法相关的安全漏洞，帮助开发人员和安全测试人员发现潜在的安全隐患。

特性
扫描HTTP响应头漏洞：

缺少常见的安全响应头（如 X-Frame-Options、Content-Security-Policy）。
Set-Cookie 头是否缺失 HttpOnly 属性。
检测 Strict-Transport-Security、X-Content-Type-Options 等头部的配置问题。
检查是否泄露服务器版本信息（如 nginx、Apache 等）。
检查CORS配置问题：识别不当的跨域资源共享配置。

缓存控制漏洞检测：识别不当的 Cache-Control 配置，如 no-cache。

HTTP请求方法漏洞：检测是否允许不安全的HTTP请求方法（如 PUT、DELETE、TRACE、MOVE）。

安装
克隆本仓库
bash
复制代码
git clone https://github.com/your-username/xiao_scanning.git
cd xiao_scanning
安装依赖
bash
复制代码
go mod tidy
使用方法
1. 显示帮助信息
bash
复制代码
go run main.go -h
2. 扫描单个URL
bash
复制代码
go run main.go -u "http://example.com"
3. 扫描多个URL（空格分隔）
bash
复制代码
go run main.go -u "http://example.com http://another-example.com"
4. 扫描URL列表文件
首先，准备一个包含URL的文本文件，每行一个URL。例如：

arduino
复制代码
http://example.com
http://another-example.com
然后使用以下命令扫描：

bash
复制代码
go run main.go -U "urls.txt"
输出示例
扫描结果将显示在终端中，显示内容包括HTTP响应头的详细信息和发现的漏洞。

示例输出：

less
复制代码
=> 扫描 Headers 相关漏洞

[*] X-Frame-Options : SAMEORIGIN
[*] Content-Security-Policy : default-src 'self'
[*] Set-Cookie : sessionid=12345; HttpOnly; Secure
[*] Strict-Transport-Security : max-age=31536000; includeSubDomains
[*] X-Content-Type-Options : nosniff
[*] Server header: nginx
[+] Found potential version leakage in Server header

=> 扫描 HTTP 请求相关漏洞

[*] Found potentially dangerous HTTP method: PUT
漏洞类型说明
1. 响应头漏洞
Set-Cookie 缺失 HttpOnly：如果 Set-Cookie 头没有包含 HttpOnly 属性，可能导致跨站脚本（XSS）攻击的风险。
Server信息泄露：服务器的 Server 头部如果包含版本信息，可能泄露服务器的详细信息，导致被攻击者利用。
2. CORS 配置问题
**Access-Control-Allow-Origin: ***：如果CORS配置为允许所有域名访问（*），可能导致跨站请求伪造（CSRF）攻击。
3. 缓存控制问题
Cache-Control: no-cache：不当的缓存控制可能导致敏感信息泄露或缓存污染。
4. HTTP请求方法漏洞
PUT、DELETE、TRACE、MOVE方法：这些方法允许用户对服务器进行修改或执行其他危险操作，应该根据需求限制或禁用。
贡献
如果你发现任何bug，或有改进建议，欢迎提issues或提交pull requests！

免责声明
该工具仅供合法的安全测试与学习使用，请勿用于任何非法活动。
