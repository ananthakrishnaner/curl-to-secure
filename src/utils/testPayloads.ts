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
  const basicTests: TestResult[] = [
    {
      id: 'auth_missing',
      name: 'Authentication Bypass Testing',
      status: 'failed',
      description: 'Testing requests without authentication headers',
      details: ['Removing Authorization header', 'Testing with empty token', 'Checking authentication bypass'],
      severity: 'High',
      request: { ...parsed, headers: { ...parsed.headers, Authorization: '' } },
      response: {
        status: 401,
        statusText: 'Unauthorized',
        headers: { 'Content-Type': 'application/json' },
        body: { error: 'Authentication required' },
        time: 150
      }
    },
    {
      id: 'bola_test',
      name: 'Broken Object Level Authorization (BOLA)',
      status: 'warning',
      description: 'Testing access to objects belonging to other users',
      details: ['Testing with different user IDs', 'Checking object ownership validation', 'Parameter manipulation'],
      severity: 'High',
      request: { 
        ...parsed, 
        body: parsed.body ? { ...parsed.body, userId: (parsed.body.userId || 123) + 999 } : null 
      },
      response: {
        status: 403,
        statusText: 'Forbidden',
        headers: { 'Content-Type': 'application/json' },
        body: { error: 'Access denied to resource' },
        time: 180
      }
    },
    {
      id: 'input_validation',
      name: 'Input Validation Testing',
      status: 'warning',
      description: 'Testing SQL injection and XSS in parameters',
      details: ['SQL injection payloads', 'XSS script injection', 'Command injection attempts'],
      severity: 'Medium',
      request: { 
        ...parsed, 
        body: parsed.body ? { ...parsed.body, malicious: "'; DROP TABLE users; --", xss: "<script>alert('xss')</script>" } : null 
      },
      response: {
        status: 400,
        statusText: 'Bad Request',
        headers: { 'Content-Type': 'application/json' },
        body: { error: 'Invalid input detected' },
        time: 200
      }
    },
    {
      id: 'rate_limiting',
      name: 'Rate Limiting Testing',
      status: 'failed',
      description: 'Testing API rate limits and throttling',
      details: ['Sending burst requests', 'Testing rate limit bypass', 'Checking throttling mechanisms'],
      severity: 'Medium',
      request: parsed,
      response: {
        status: 429,
        statusText: 'Too Many Requests',
        headers: { 'Content-Type': 'application/json', 'Retry-After': '60' },
        body: { error: 'Rate limit exceeded' },
        time: 50
      }
    },
    {
      id: 'headers_security',
      name: 'Security Headers Check',
      status: 'warning',
      description: 'Checking for missing security headers',
      details: ['CORS headers validation', 'Content-Security-Policy check', 'X-Frame-Options verification'],
      severity: 'Low',
      request: parsed,
      response: {
        status: 200,
        statusText: 'OK',
        headers: { 'Content-Type': 'application/json' },
        body: { success: true, message: 'Missing security headers' },
        time: 120
      }
    }
  ];

  const advancedTests: TestResult[] = [
    ...basicTests,
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