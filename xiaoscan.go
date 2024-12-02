package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

var allVuln = make(map[string][]string)

// 打印banner信息
func banner() {
	banners := []string{
		`
      _                                 
     (_)                                 
__  ___  __ _  ___  ___  ___ __ _ _ __  
\ \/ / |/ _ |/ _ \/ __|/ __/ _ | '_ \ 
 >  <| | (_| | (_) \__ \ (_| (_| | | | |
/_/\_\_|\__,_|\___/|___/\___\__,_|_| |_| 
                                            Auth0r:xiao`,
		`https://github.com/Jason3329/xiao_scanning`,
	}
	rand.Seed(time.Now().Unix()) // Seed the random number generator
	randIndex := rand.Intn(len(banners)) // Generate a random index
	fmt.Println(banners[randIndex])
}
// 扫描单个URL
func scanSingle(url string) {
	color.Green("=>扫描Headers相关漏洞")

	// 获取HTTP响应头
	headers, err := getHeaders(url)
	if err != nil {
		color.Red("[!] 获取Headers失败: %v", err)
		return
	}

	// 打印响应头
	for key, value := range headers {
		color.Yellow("\t   %s : %s", key, value)
	}

	fmt.Println(strings.Repeat("- ", 20))

	// 执行各类漏洞检查
	vulnResult1 := getHeadersVuln(headers)
	vulnResult2 := checkServerLeakage(headers)
	vulnResult3 := checkCORS(headers)
	vulnResult4 := checkCacheControl(headers)

	color.Green("=>扫描HTTP请求相关漏洞")
	vulnResult5 := getOptionsVuln(url)

	// 将扫描结果添加到所有漏洞中
	allVuln[url] = append(allVuln[url], vulnResult1...)
	allVuln[url] = append(allVuln[url], vulnResult2...)
	allVuln[url] = append(allVuln[url], vulnResult3...)
	allVuln[url] = append(allVuln[url], vulnResult4...)
	allVuln[url] = append(allVuln[url], vulnResult5...)
	fmt.Println(strings.Repeat("_", 60))
}

// 获取HTTP响应头
func getHeaders(url string) (map[string]string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// 设置User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36")
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 读取并返回响应头
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}
	color.Yellow("[*] GET method Headers Response: %d", resp.StatusCode)
	return headers, nil
}

// 检查HTTP响应头中的漏洞
func getHeadersVuln(headers map[string]string) []string {
	var result []string
	vulnHeaders := map[string]string{
		"X-Frame-Options":       ".*",
		"Content-Security-Policy": ".*",
		"Set-Cookie":             ".*",
		"Strict-Transport-Security": "",
		"X-Content-Type-Options": "",
	}

	// 检查每个头部字段是否存在漏洞
	for key := range vulnHeaders {
		if value, exists := headers[key]; exists {
			color.Cyan("[*] %s : %s", key, value)
			// 检查 Set-Cookie 是否包含 HttpOnly
			if key == "Set-Cookie" && !strings.Contains(strings.ToLower(value), "httponly") {
				result = append(result, "(响应头缺失类) Set-Cookie 缺失 HttpOnly")
				color.Red("[+] (响应头缺失类)\tFind vuln: HttpOnly 缺失")
			}
		} else {
			result = append(result, fmt.Sprintf("(响应头缺失类) %s 头缺失", key))
			color.Red("[+] (响应头缺失类)\tFind vuln: %s 头缺失", key)
		}
	}
	return result
}

// 检查Server头信息泄露漏洞
func checkServerLeakage(headers map[string]string) []string {
	var result []string
	server := headers["Server"]
	if server != "" {
		color.Cyan("[*] Server header: %s", server)
		if strings.Contains(server, "nginx") || strings.Contains(server, "Apache") {
			result = append(result, "(信息泄露类) Server header contains version info: "+server)
			color.Red("[+] Found potential version leakage in Server header")
		}
	}
	return result
}

// 检查CORS配置漏洞
func checkCORS(headers map[string]string) []string {
	var result []string
	// 检查是否存在漏洞的CORS配置
	if cors := headers["Access-Control-Allow-Origin"]; cors == "*" {
		result = append(result, "(CORS 配置不当) Access-Control-Allow-Origin: *")
		color.Red("[+] CORS misconfiguration: Access-Control-Allow-Origin is '*'")
	}
	return result
}

// 检查Cache-Control配置漏洞
func checkCacheControl(headers map[string]string) []string {
	var result []string
	// 检查是否存在不当的Cache-Control配置
	if cacheControl := headers["Cache-Control"]; cacheControl == "no-cache" {
		result = append(result, "(Cache-Control 配置不当) Cache-Control: no-cache")
		color.Red("[+] Cache-Control misconfiguration: no-cache found")
	}
	return result
}

// 检查HTTP请求方法漏洞
func getOptionsVuln(url string) []string {
	var result []string
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, _ := http.NewRequest("OPTIONS", url, nil)
	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		if allow := resp.Header.Get("Allow"); allow != "" {
			// 检查是否允许危险的HTTP方法
			methods := []string{"PUT", "DELETE", "TRACE", "MOVE"}
			for _, method := range methods {
				if strings.Contains(allow, method) {
					result = append(result, fmt.Sprintf("(不安全HTTP方法) 允许方法: %s", method))
					color.Red("[+] Found potentially dangerous HTTP method: %s", method)
				}
			}
		}
	}
	return result
}

// 从文件中读取URL
func readURLsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}

func main() {
	helpFlag := flag.Bool("h", false, "显示帮助信息")
	urlsFlag := flag.String("u", "", "要扫描的URL列表，空格分隔")
	fileFlag := flag.String("U", "", "包含URL列表的txt文件路径，每行一个URL")
	flag.Parse()

	// 显示banner信息
	banner()

	// 如果用户请求帮助，则显示帮助信息
	if *helpFlag {
		flag.Usage()
		return
	}

	var urls []string

	// 根据用户输入的URL列表或文件路径获取URL
	if *urlsFlag != "" {
		urls = strings.Fields(*urlsFlag)
	} else if *fileFlag != "" {
		var err error
		urls, err = readURLsFromFile(*fileFlag)
		if err != nil {
			color.Red("[!] 无法读取文件: %v", err)
			return
		}
	} else {
		color.Red("[!] 请使用 -u 传递URL或 -U 传递包含URL的文件路径")
		return
	}

	// 执行扫描
	for _, url := range urls {
		fmt.Println("\n开始扫描 -->", url)
		// 确保URL以http://或https://开头
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}
		scanSingle(url)
	}

	color.Green("扫描完毕")
}
