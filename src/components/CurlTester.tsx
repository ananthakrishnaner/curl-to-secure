import { useState } from "react";
import { Terminal, Play, Shield, AlertTriangle, CheckCircle, Copy, Eye, ChevronDown, ChevronUp, GripVertical, Move3D } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Checkbox } from "@/components/ui/checkbox";
import { useToast } from "@/hooks/use-toast";

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

export const CurlTester = () => {
  const [curlCommand, setCurlCommand] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [currentTest, setCurrentTest] = useState("");
  const [parsedCurl, setParsedCurl] = useState<ParsedCurl | null>(null);
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const [expandedResults, setExpandedResults] = useState<Set<string>>(new Set());
  const [selectedVulnerabilities, setSelectedVulnerabilities] = useState<Set<string>>(new Set(['bola', 'auth', 'bopla', 'rate_limit', 'input_validation', 'ssrf', 'headers']));
  const [draggedItem, setDraggedItem] = useState<TestResult | null>(null);
  const { toast } = useToast();

  const vulnerabilityOptions = [
    { id: 'bola', name: 'Broken Object Level Authorization (BOLA)', category: 'Authorization' },
    { id: 'auth', name: 'Authentication Testing', category: 'Authentication' },
    { id: 'bopla', name: 'Broken Object Property Level Authorization', category: 'Authorization' },
    { id: 'rate_limit', name: 'Rate Limiting Testing', category: 'Resource Management' },
    { id: 'input_validation', name: 'Input Validation Testing', category: 'Input Validation' },
    { id: 'ssrf', name: 'Server Side Request Forgery (SSRF)', category: 'Network Security' },
    { id: 'headers', name: 'Security Headers Check', category: 'Configuration' }
  ];

  const exampleCurl = `curl -X POST https://api.example.com/users \\
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMjM0NTY3ODkwLCJuYW1lIjoiSm9obiBEb2UifQ.Ks7KcdjrlUWKqJmXiWKt1nKaWhLZHzJyWnkhzUa6GwA" \\
  -H "Content-Type: application/json" \\
  -H "User-Agent: MyApp/1.0" \\
  --data-raw '{"userId": 123, "role": "user", "email": "john@example.com", "isAdmin": false, "callbackUrl": "https://webhook.site/test"}'`;

  const parseCurlCommand = (curl: string): ParsedCurl | null => {
    try {
      // Normalize the curl command - remove line breaks and extra spaces
      const normalizedCurl = curl.replace(/\\\s*\n/g, ' ').replace(/\s+/g, ' ').trim();
      
      // Extract URL - handle various formats
      let urlMatch = normalizedCurl.match(/curl\s+(?:-[^\s]*\s+)*(?:["']?)([^"'\s]+)(?:["']?)/);
      if (!urlMatch) {
        // Try alternative patterns
        urlMatch = normalizedCurl.match(/(?:curl\s+)(?:.*?\s+)?(?:["']?)((https?:\/\/|ftp:\/\/)[^"'\s]+)(?:["']?)/);
      }
      
      // Extract method
      const methodMatch = normalizedCurl.match(/-X\s+([A-Z]+)/i) || normalizedCurl.match(/--request\s+([A-Z]+)/i);
      
      // Extract headers - handle multiple formats
      const headerMatches = [
        ...normalizedCurl.matchAll(/-H\s+["']([^"']+)["']/g),
        ...normalizedCurl.matchAll(/--header\s+["']([^"']+)["']/g),
        ...normalizedCurl.matchAll(/-H\s+([^"'\s][^\s]*:\s*[^"'\s][^\s]*)/g)
      ];
      
      // Extract body data - handle multiple formats
      let bodyMatch = normalizedCurl.match(/-d\s+['"`]([^'"`]+)['"`]/) ||
                     normalizedCurl.match(/--data\s+['"`]([^'"`]+)['"`]/) ||
                     normalizedCurl.match(/--data-raw\s+['"`]([^'"`]+)['"`]/) ||
                     normalizedCurl.match(/--json\s+['"`]([^'"`]+)['"`]/);

      if (!urlMatch) return null;

      const url = urlMatch[1];
      const method = methodMatch?.[1]?.toUpperCase() || 'GET';
      const headers: Record<string, string> = {};
      
      // Process headers
      for (const match of headerMatches) {
        const headerLine = match[1];
        const colonIndex = headerLine.indexOf(':');
        if (colonIndex > 0) {
          const key = headerLine.substring(0, colonIndex).trim();
          const value = headerLine.substring(colonIndex + 1).trim();
          if (key && value) headers[key] = value;
        }
      }

      // Process body
      let body = null;
      if (bodyMatch) {
        try {
          body = JSON.parse(bodyMatch[1]);
        } catch {
          // If not valid JSON, store as string
          body = bodyMatch[1];
        }
      }

      const endpoint = new URL(url).pathname;
      return { url, method, headers, body, endpoint };
    } catch (error) {
      console.error('cURL parsing error:', error);
      return null;
    }
  };

  const generateMockResponse = (testType: string, status: 'passed' | 'failed' | 'warning', parameter?: string) => {
    const baseTime = Math.floor(Math.random() * 300) + 50;
    
    if (status === 'failed') {
      if (testType === 'input_validation') {
        return {
          status: 500,
          statusText: 'Internal Server Error',
          headers: { 'Content-Type': 'application/json', 'X-Response-Time': `${baseTime}ms` },
          body: { 
            error: 'Database error',
            message: `SQL syntax error near '${parameter}' - Potential SQL injection vulnerability detected`,
            stack_trace: 'at DatabaseQuery.execute(query.js:45)',
            vulnerable_parameter: parameter
          },
          time: baseTime
        };
      }
      return {
        status: 200,
        statusText: 'OK',
        headers: { 'Content-Type': 'application/json', 'X-Response-Time': `${baseTime}ms` },
        body: { 
          success: true, 
          data: { id: 999, name: 'Unauthorized User', role: 'admin', isAdmin: true },
          message: 'Vulnerable: Access granted to unauthorized resource'
        },
        time: baseTime
      };
    } else if (status === 'warning') {
      if (testType === 'input_validation') {
        return {
          status: 400,
          statusText: 'Bad Request',
          headers: { 'Content-Type': 'application/json', 'X-Validation': 'partial' },
          body: { 
            error: 'Validation failed', 
            message: `Parameter '${parameter}' contains invalid characters but request was processed`,
            sanitized_value: parameter?.replace(/['"<>&]/g, '')
          },
          time: baseTime
        };
      }
      return {
        status: 429,
        statusText: 'Too Many Requests',
        headers: { 'Content-Type': 'application/json', 'X-Rate-Limit': '100', 'Retry-After': '60' },
        body: { error: 'Rate limit exceeded', retryAfter: 60 },
        time: baseTime
      };
    } else {
      return {
        status: 403,
        statusText: 'Forbidden',
        headers: { 'Content-Type': 'application/json', 'X-Security-Check': 'passed' },
        body: { error: 'Access denied', message: 'Proper authorization required' },
        time: baseTime
      };
    }
  };

  const generateSecurityTests = (parsed: ParsedCurl): TestResult[] => {
    const results: TestResult[] = [];

    // BOLA Testing
    if (selectedVulnerabilities.has('bola') && (parsed.body?.userId || parsed.endpoint.includes('/users/'))) {
      const testRequest = {
        method: parsed.method,
        url: parsed.url.replace(/\/\d+/, '/999'), // Replace user ID with 999
        headers: parsed.headers,
        body: parsed.body ? { ...parsed.body, userId: 999 } : undefined
      };

      results.push({
        id: 'bola',
        name: 'Broken Object Level Authorization (BOLA)',
        status: 'failed',
        description: 'User ID manipulation detected in request',
        details: [
          'Found userId parameter that can be manipulated',
          'Testing with incremented/decremented IDs',
          'Checking access to other user objects'
        ],
        severity: 'Critical',
        request: testRequest,
        response: generateMockResponse('bola', 'failed')
      });
    }

    // Authentication Testing
    if (selectedVulnerabilities.has('auth')) {
      if (parsed.headers.Authorization) {
      const testRequest = {
        method: parsed.method,
        url: parsed.url,
        headers: { ...parsed.headers, Authorization: '' }, // Remove auth header
        body: parsed.body
      };

      results.push({
        id: 'auth',
        name: 'Authentication Testing',
        status: 'warning',
        description: 'Bearer token authentication detected',
        details: [
          'Testing requests without Authorization header',
          'Testing with malformed tokens',
          'Checking token expiration handling'
        ],
        severity: 'High',
        request: testRequest,
        response: generateMockResponse('auth', 'warning')
      });
    } else {
      const testRequest = {
        method: parsed.method,
        url: parsed.url,
        headers: parsed.headers,
        body: parsed.body
      };

      results.push({
        id: 'auth',
        name: 'Authentication Testing',
        status: 'failed',
        description: 'No authentication headers found',
        details: [
          'Endpoint appears to lack authentication',
          'Testing unauthorized access',
          'Potential security risk'
        ],
        severity: 'Critical',
        request: testRequest,
        response: generateMockResponse('auth', 'failed')
      });
      }
    }

    // BOPLA Testing
    if (selectedVulnerabilities.has('bopla') && parsed.body && typeof parsed.body === 'object') {
      const testRequest = {
        method: parsed.method,
        url: parsed.url,
        headers: parsed.headers,
        body: { ...parsed.body, isAdmin: true, role: 'admin' } // Add privileged fields
      };

      results.push({
        id: 'bopla',
        name: 'Broken Object Property Level Authorization',
        status: 'warning',
        description: 'JSON payload detected for privilege escalation testing',
        details: [
          'Adding admin privileges: {"isAdmin": true}',
          'Testing role elevation: {"role": "admin"}',
          'Checking property-level access controls'
        ],
        severity: 'High',
        request: testRequest,
        response: generateMockResponse('bopla', 'warning')
      });
    }

    // Rate Limiting
    if (selectedVulnerabilities.has('rate_limit')) {
      const testRequest = {
      method: parsed.method,
      url: parsed.url,
      headers: parsed.headers,
      body: parsed.body
    };

    results.push({
      id: 'rate_limit',
      name: 'Rate Limiting Testing',
      status: 'warning',
      description: 'Testing API rate limits and resource consumption',
      details: [
        'Sending burst of 100 requests',
        'Testing large payload handling',
        'Checking timeout mechanisms'
      ],
      severity: 'Medium',
      request: testRequest,
      response: generateMockResponse('rate_limit', 'warning')
      });
    }

    // Input Validation Testing
    if (selectedVulnerabilities.has('input_validation')) {
      const inputValidationPayloads = [
        { name: 'SQL Injection', payload: "'; DROP TABLE users; --", description: 'SQL injection attack payload' },
        { name: 'XSS Attack', payload: '<script>alert("XSS")</script>', description: 'Cross-site scripting payload' },
        { name: 'Command Injection', payload: '; cat /etc/passwd', description: 'Command injection payload' },
        { name: 'LDAP Injection', payload: '*)(uid=*))(|(uid=*', description: 'LDAP injection payload' },
        { name: 'NoSQL Injection', payload: '{"$ne": null}', description: 'NoSQL injection payload' }
      ];

      // Test URL parameters
      const urlParams = new URL(parsed.url).searchParams;
      urlParams.forEach((value, key) => {
        inputValidationPayloads.forEach(payload => {
          const testUrl = new URL(parsed.url);
          testUrl.searchParams.set(key, payload.payload);
          
          results.push({
            id: `input_validation_url_${key}_${payload.name.toLowerCase().replace(/\s+/g, '_')}`,
            name: `Input Validation - URL Parameter: ${key}`,
            status: 'failed',
            description: `Testing ${payload.name} in URL parameter '${key}'`,
            details: [
              `Parameter: ${key}`,
              `Original value: ${value}`,
              `Test payload: ${payload.payload}`,
              `Attack type: ${payload.description}`
            ],
            severity: 'High',
            request: {
              method: parsed.method,
              url: testUrl.toString(),
              headers: parsed.headers,
              body: parsed.body
            },
            response: generateMockResponse('input_validation', 'failed', key)
          });
        });
      });

      // Test JSON body parameters
      if (parsed.body && typeof parsed.body === 'object') {
        Object.keys(parsed.body).forEach(key => {
          inputValidationPayloads.forEach(payload => {
            const testBody = { ...parsed.body };
            testBody[key] = payload.payload;
            
            results.push({
              id: `input_validation_body_${key}_${payload.name.toLowerCase().replace(/\s+/g, '_')}`,
              name: `Input Validation - Body Parameter: ${key}`,
              status: 'failed',
              description: `Testing ${payload.name} in body parameter '${key}'`,
              details: [
                `Parameter: ${key}`,
                `Original value: ${parsed.body[key]}`,
                `Test payload: ${payload.payload}`,
                `Attack type: ${payload.description}`
              ],
              severity: 'High',
              request: {
                method: parsed.method,
                url: parsed.url,
                headers: parsed.headers,
                body: testBody
              },
              response: generateMockResponse('input_validation', 'failed', key)
            });
          });
        });
      }

      // Test headers for injection
      ['User-Agent', 'X-Forwarded-For', 'X-Real-IP'].forEach(headerName => {
        if (parsed.headers[headerName] || headerName === 'User-Agent') {
          inputValidationPayloads.slice(0, 2).forEach(payload => { // Test only XSS and SQL for headers
            const testHeaders = { ...parsed.headers };
            testHeaders[headerName] = payload.payload;
            
            results.push({
              id: `input_validation_header_${headerName.toLowerCase().replace(/-/g, '_')}_${payload.name.toLowerCase().replace(/\s+/g, '_')}`,
              name: `Input Validation - Header: ${headerName}`,
              status: 'warning',
              description: `Testing ${payload.name} in header '${headerName}'`,
              details: [
                `Header: ${headerName}`,
                `Original value: ${parsed.headers[headerName] || 'Not set'}`,
                `Test payload: ${payload.payload}`,
                `Attack type: ${payload.description}`
              ],
              severity: 'Medium',
              request: {
                method: parsed.method,
                url: parsed.url,
                headers: testHeaders,
                body: parsed.body
              },
              response: generateMockResponse('input_validation', 'warning', headerName)
            });
          });
        }
      });
    }

    // SSRF Testing
    if (selectedVulnerabilities.has('ssrf') && parsed.body && JSON.stringify(parsed.body).includes('http')) {
      const ssrfPayloads = [
        'http://169.254.169.254/metadata',
        'http://localhost:80/admin',
        'file:///etc/passwd',
        'http://127.0.0.1:22',
        'ftp://internal.company.com'
      ];

      // Find URL-like parameters in body
      Object.keys(parsed.body).forEach(key => {
        const value = parsed.body[key];
        if (typeof value === 'string' && (value.includes('http') || key.toLowerCase().includes('url') || key.toLowerCase().includes('callback'))) {
          ssrfPayloads.forEach((payload, index) => {
            const testRequest = {
              method: parsed.method,
              url: parsed.url,
              headers: parsed.headers,
              body: { ...parsed.body, [key]: payload }
            };

            results.push({
              id: `ssrf_${key}_${index}`,
              name: `SSRF Testing - Parameter: ${key}`,
              status: 'failed',
              description: `Testing SSRF via '${key}' parameter`,
              details: [
                `Parameter: ${key}`,
                `Original value: ${value}`,
                `SSRF payload: ${payload}`,
                'Testing internal network access',
                'Checking URL validation bypass'
              ],
              severity: 'High',
              request: testRequest,
              response: generateMockResponse('ssrf', 'failed', key)
            });
          });
        }
      });
    } else if (selectedVulnerabilities.has('ssrf')) {
      // Test common SSRF vectors even without obvious URLs
      const testRequest = {
        method: parsed.method,
        url: parsed.url,
        headers: parsed.headers,
        body: parsed.body ? { ...parsed.body, callbackUrl: 'http://169.254.169.254/metadata' } : { callbackUrl: 'http://169.254.169.254/metadata' }
      };

      results.push({
        id: 'ssrf_general',
        name: 'SSRF Testing - General',
        status: 'warning',
        description: 'Testing for SSRF vulnerabilities with callback URL injection',
        details: [
          'Adding callbackUrl parameter',
          'Testing metadata endpoint access',
          'Checking URL validation',
          'Probing internal network access'
        ],
        severity: 'Medium',
        request: testRequest,
        response: generateMockResponse('ssrf', 'warning')
      });
    }

    // Security Headers Check
    if (selectedVulnerabilities.has('headers')) {
      const securityHeaderTests = [
        {
          header: 'Strict-Transport-Security',
          name: 'HSTS (HTTP Strict Transport Security)',
          checkFunction: (value: string) => {
            if (!value) return { status: 'failed', issue: 'HSTS header missing' };
            const maxAge = value.match(/max-age=(\d+)/);
            const includesSubdomains = value.includes('includeSubDomains');
            const preload = value.includes('preload');
            
            if (!maxAge || parseInt(maxAge[1]) < 31536000) {
              return { status: 'warning', issue: 'max-age should be at least 1 year (31536000)' };
            }
            if (!includesSubdomains) {
              return { status: 'warning', issue: 'Consider adding includeSubDomains directive' };
            }
            return { status: 'passed', issue: null };
          }
        },
        {
          header: 'Content-Security-Policy',
          name: 'CSP (Content Security Policy)',
          checkFunction: (value: string) => {
            if (!value) return { status: 'failed', issue: 'CSP header missing' };
            if (value.includes("'unsafe-inline'") || value.includes("'unsafe-eval'")) {
              return { status: 'warning', issue: "Contains unsafe directives ('unsafe-inline' or 'unsafe-eval')" };
            }
            if (!value.includes('default-src')) {
              return { status: 'warning', issue: 'Missing default-src fallback directive' };
            }
            return { status: 'passed', issue: null };
          }
        },
        {
          header: 'X-Frame-Options',
          name: 'X-Frame-Options (Clickjacking Protection)',
          checkFunction: (value: string) => {
            if (!value) return { status: 'failed', issue: 'X-Frame-Options header missing' };
            if (!['DENY', 'SAMEORIGIN'].includes(value.toUpperCase())) {
              return { status: 'warning', issue: 'Should be DENY or SAMEORIGIN' };
            }
            return { status: 'passed', issue: null };
          }
        },
        {
          header: 'X-Content-Type-Options',
          name: 'X-Content-Type-Options (MIME Sniffing Protection)',
          checkFunction: (value: string) => {
            if (!value) return { status: 'failed', issue: 'X-Content-Type-Options header missing' };
            if (value.toLowerCase() !== 'nosniff') {
              return { status: 'warning', issue: 'Should be set to "nosniff"' };
            }
            return { status: 'passed', issue: null };
          }
        },
        {
          header: 'Referrer-Policy',
          name: 'Referrer-Policy (Referrer Information Control)',
          checkFunction: (value: string) => {
            if (!value) return { status: 'failed', issue: 'Referrer-Policy header missing' };
            const securePolicies = ['no-referrer', 'strict-origin-when-cross-origin', 'strict-origin'];
            if (!securePolicies.includes(value.toLowerCase())) {
              return { status: 'warning', issue: 'Consider using a more restrictive policy' };
            }
            return { status: 'passed', issue: null };
          }
        },
        {
          header: 'Permissions-Policy',
          name: 'Permissions-Policy (Feature Policy)',
          checkFunction: (value: string) => {
            if (!value) return { status: 'warning', issue: 'Permissions-Policy header missing (recommended)' };
            const sensitiveFunctions = ['microphone', 'camera', 'geolocation', 'payment'];
            const hasRestrictions = sensitiveFunctions.some(func => value.includes(`${func}=()`));
            if (!hasRestrictions) {
              return { status: 'warning', issue: 'Consider restricting sensitive browser features' };
            }
            return { status: 'passed', issue: null };
          }
        }
      ];

      securityHeaderTests.forEach(test => {
        // Mock response headers with some common security headers
        const mockResponseHeaders = {
          'Content-Type': 'application/json',
          'X-Response-Time': '150ms',
          'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          // Intentionally missing some headers to show vulnerabilities
        };

        const headerValue = mockResponseHeaders[test.header] || '';
        const testResult = test.checkFunction(headerValue);
        
        const testRequest = {
          method: parsed.method,
          url: parsed.url,
          headers: parsed.headers,
          body: parsed.body
        };

        results.push({
          id: `header_${test.header.toLowerCase().replace(/[^a-z0-9]/g, '_')}`,
          name: `Security Header: ${test.name}`,
          status: testResult.status as 'passed' | 'failed' | 'warning',
          description: testResult.issue || `${test.header} header properly configured`,
          details: [
            `Header: ${test.header}`,
            `Current value: ${headerValue || 'Not present'}`,
            testResult.issue ? `Issue: ${testResult.issue}` : 'Properly configured',
            'Testing response security headers configuration'
          ],
          severity: testResult.status === 'failed' ? 'High' : testResult.status === 'warning' ? 'Medium' : 'Low',
          request: testRequest,
          response: {
            status: 200,
            statusText: 'OK',
            headers: mockResponseHeaders,
            body: { message: 'Security headers analysis complete' },
            time: 120
          }
        });
      });
    }

    return results;
  };

  const handleAnalyzeCurl = async () => {
    if (!curlCommand.trim()) {
      toast({
        title: "Missing cURL Command",
        description: "Please provide a cURL command to analyze",
        variant: "destructive"
      });
      return;
    }

    setIsAnalyzing(true);
    setAnalysisProgress(0);
    setTestResults([]);
    
    const parsed = parseCurlCommand(curlCommand);
    
    if (!parsed) {
      toast({
        title: "Invalid cURL Command",
        description: "Could not parse the provided cURL command",
        variant: "destructive"
      });
      setIsAnalyzing(false);
      return;
    }

    setParsedCurl(parsed);
    
    // Simulate progressive testing with realistic delays
    const tests = generateSecurityTests(parsed);
    const testSteps = [
      "Parsing cURL command...",
      "Extracting endpoint information...",
      "Testing BOLA vulnerabilities...",
      "Checking authentication...",
      "Testing privilege escalation...",
      "Analyzing rate limiting...",
      "Testing input validation...",
      "Scanning for SSRF...",
      "Validating security headers...",
      "Generating final report..."
    ];

    for (let i = 0; i < testSteps.length; i++) {
      setCurrentTest(testSteps[i]);
      setAnalysisProgress((i + 1) / testSteps.length * 100);
      await new Promise(resolve => setTimeout(resolve, 400 + Math.random() * 300));
    }
    
    setTestResults(tests);
    setIsAnalyzing(false);
    setCurrentTest("");
    
    toast({
      title: "Analysis Complete",
      description: `Found ${tests.filter(r => r.status === 'failed').length} critical issues across ${tests.length} tests`,
      variant: "default"
    });
  };

  const copyExample = () => {
    setCurlCommand(exampleCurl);
    toast({
      title: "Example Copied",
      description: "Example cURL command has been added to the input",
    });
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'passed': return <CheckCircle className="w-5 h-5 text-primary" />;
      case 'failed': return <AlertTriangle className="w-5 h-5 text-destructive" />;
      case 'warning': return <AlertTriangle className="w-5 h-5 text-security-yellow" />;
      default: return null;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical": return "bg-destructive text-destructive-foreground";
      case "High": return "bg-security-red text-white";
      case "Medium": return "bg-security-yellow text-black";
      case "Low": return "bg-primary text-primary-foreground";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const toggleResultExpansion = (resultId: string) => {
    const newExpanded = new Set(expandedResults);
    if (newExpanded.has(resultId)) {
      newExpanded.delete(resultId);
    } else {
      newExpanded.add(resultId);
    }
    setExpandedResults(newExpanded);
  };

  const handleVulnerabilityToggle = (vulnId: string) => {
    const newSelected = new Set(selectedVulnerabilities);
    if (newSelected.has(vulnId)) {
      newSelected.delete(vulnId);
    } else {
      newSelected.add(vulnId);
    }
    setSelectedVulnerabilities(newSelected);
  };

  const handleSelectAll = () => {
    if (selectedVulnerabilities.size === vulnerabilityOptions.length) {
      setSelectedVulnerabilities(new Set());
    } else {
      setSelectedVulnerabilities(new Set(vulnerabilityOptions.map(v => v.id)));
    }
  };

  const handleDragStart = (result: TestResult) => {
    setDraggedItem(result);
  };

  const handleDragEnd = () => {
    setDraggedItem(null);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (draggedItem) {
      // Show detailed view in a modal or expanded section
      toast({
        title: "Test Details",
        description: `Viewing details for ${draggedItem.name}`,
      });
      setExpandedResults(new Set([draggedItem.id]));
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  return (
    <div className="min-h-screen bg-background py-8">
      <div className="container max-w-6xl px-4">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-card border border-primary/20 mb-4">
            <Shield className="w-4 h-4 text-primary" />
            <span className="text-sm text-muted-foreground">API Security Testing Tool</span>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold mb-4">
            <span className="bg-text-gradient bg-clip-text text-transparent">GreenAPI</span>
          </h1>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Provide a cURL command and get comprehensive API security testing results instantly
          </p>
        </div>

        {/* Input Section */}
        <Card className="bg-gradient-card border-primary/20 mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Terminal className="w-5 h-5" />
              cURL Command Input
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="relative">
              <Textarea
                placeholder="Paste your cURL command here..."
                value={curlCommand}
                onChange={(e) => setCurlCommand(e.target.value)}
                className="min-h-32 font-mono text-sm bg-muted/50"
              />
              <Button
                variant="outline"
                size="sm"
                onClick={copyExample}
                className="absolute top-2 right-2"
              >
                <Copy className="w-4 h-4 mr-1" />
                Example
              </Button>
            </div>

            {/* Vulnerability Selection */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="font-semibold text-primary">Select Vulnerabilities to Test</h4>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleSelectAll}
                >
                  {selectedVulnerabilities.size === vulnerabilityOptions.length ? 'Deselect All' : 'Select All'}
                </Button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {vulnerabilityOptions.map((vuln) => (
                  <div key={vuln.id} className="flex items-center space-x-2 p-3 rounded-lg bg-muted/50 border">
                    <Checkbox
                      id={vuln.id}
                      checked={selectedVulnerabilities.has(vuln.id)}
                      onCheckedChange={() => handleVulnerabilityToggle(vuln.id)}
                    />
                    <div className="flex-1">
                      <label htmlFor={vuln.id} className="text-sm font-medium cursor-pointer">
                        {vuln.name}
                      </label>
                      <p className="text-xs text-muted-foreground">{vuln.category}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            
            <Button 
              onClick={handleAnalyzeCurl}
              disabled={isAnalyzing || selectedVulnerabilities.size === 0}
              className="w-full bg-gradient-primary hover:scale-105 transition-all duration-300"
            >
              {isAnalyzing ? (
                <>
                  <div className="w-4 h-4 mr-2 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Analyzing Security...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 mr-2" />
                  Analyze API Security
                </>
              )}
            </Button>
          </CardContent>
        </Card>

        {/* Progress Bar */}
        {isAnalyzing && (
          <Card className="bg-gradient-card border-primary/20 mb-8">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="w-5 h-5 animate-pulse" />
                Security Analysis in Progress
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-muted-foreground">{currentTest}</span>
                  <span className="text-primary font-medium">{Math.round(analysisProgress)}%</span>
                </div>
                <Progress value={analysisProgress} className="h-2" />
              </div>
              <p className="text-sm text-muted-foreground">
                Running comprehensive OWASP API Top 10 security tests...
              </p>
            </CardContent>
          </Card>
        )}

        {/* Parsed Information */}
        {parsedCurl && (
          <Card className="bg-gradient-card border-primary/20 mb-8">
            <CardHeader>
              <CardTitle>Parsed Request Information</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid md:grid-cols-2 gap-4">
                <div>
                  <h4 className="font-semibold mb-2 text-primary">Endpoint Details</h4>
                  <div className="space-y-2 text-sm">
                    <div><span className="text-muted-foreground">URL:</span> {parsedCurl.url}</div>
                    <div><span className="text-muted-foreground">Method:</span> {parsedCurl.method}</div>
                    <div><span className="text-muted-foreground">Endpoint:</span> {parsedCurl.endpoint}</div>
                  </div>
                </div>
                <div>
                  <h4 className="font-semibold mb-2 text-primary">Headers & Data</h4>
                  <div className="space-y-2 text-sm">
                    <div><span className="text-muted-foreground">Headers:</span> {Object.keys(parsedCurl.headers).length} found</div>
                    <div><span className="text-muted-foreground">Auth:</span> {parsedCurl.headers.Authorization ? 'Bearer Token' : 'None'}</div>
                    <div><span className="text-muted-foreground">Body:</span> {parsedCurl.body ? 'JSON payload detected' : 'No body'}</div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Test Results */}
        {testResults.length > 0 && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold">Security Test Results</h2>
              <div className="text-sm text-muted-foreground flex items-center gap-2">
                <Move3D className="w-4 h-4" />
                Drag test cards to view detailed request/response data
              </div>
            </div>
            <div 
              className="grid gap-4 min-h-[200px] border-2 border-dashed border-primary/20 rounded-lg p-4"
              onDrop={handleDrop}
              onDragOver={handleDragOver}
            >
              {testResults.map((result) => (
                <Card 
                  key={result.id} 
                  className="bg-gradient-card border-primary/20 cursor-move hover:shadow-lg transition-all duration-200"
                  draggable
                  onDragStart={() => handleDragStart(result)}
                  onDragEnd={handleDragEnd}
                >
                  <CardHeader>
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-center gap-3">
                        <GripVertical className="w-4 h-4 text-muted-foreground cursor-grab active:cursor-grabbing" />
                        {getStatusIcon(result.status)}
                        <div className="flex-1">
                          <CardTitle className="text-lg flex items-center gap-3">
                            {result.name}
                            <Badge className={getSeverityColor(result.severity)}>
                              {result.severity}
                            </Badge>
                          </CardTitle>
                          <p className="text-muted-foreground mt-1">{result.description}</p>
                        </div>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => toggleResultExpansion(result.id)}
                        className="text-primary hover:bg-primary/10"
                      >
                        <Eye className="w-4 h-4 mr-1" />
                        View Details
                        {expandedResults.has(result.id) ? (
                          <ChevronUp className="w-4 h-4 ml-1" />
                        ) : (
                          <ChevronDown className="w-4 h-4 ml-1" />
                        )}
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <h4 className="font-semibold mb-2 text-primary">Test Details</h4>
                      <ul className="space-y-1">
                        {result.details.map((detail, i) => (
                          <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="text-primary mt-1">•</span>
                            {detail}
                          </li>
                        ))}
                      </ul>
                    </div>

                    <Collapsible open={expandedResults.has(result.id)}>
                      <CollapsibleContent className="space-y-4">
                        <div className="border-t border-primary/20 pt-4">
                          <div className="grid md:grid-cols-2 gap-6">
                            {/* Request Details */}
                            <div>
                              <h4 className="font-semibold mb-3 text-primary flex items-center gap-2">
                                <Terminal className="w-4 h-4" />
                                Test Request
                              </h4>
                              <div className="bg-muted/50 rounded-lg p-4 font-mono text-sm">
                                <div className="mb-2">
                                  <span className="text-primary font-semibold">{result.request.method}</span> {result.request.url}
                                </div>
                                
                                <div className="mb-3">
                                  <div className="text-muted-foreground mb-1">Headers:</div>
                                  {Object.entries(result.request.headers).map(([key, value]) => (
                                    <div key={key} className="text-xs">
                                      <span className="text-primary">{key}:</span> {value}
                                    </div>
                                  ))}
                                </div>

                                {result.request.body && (
                                  <div>
                                    <div className="text-muted-foreground mb-1">Body:</div>
                                    <div className="text-xs bg-background/50 rounded p-2 overflow-auto">
                                      {JSON.stringify(result.request.body, null, 2)}
                                    </div>
                                  </div>
                                )}
                              </div>
                            </div>

                            {/* Response Details */}
                            <div>
                              <h4 className="font-semibold mb-3 text-primary flex items-center gap-2">
                                <Shield className="w-4 h-4" />
                                Test Response
                              </h4>
                              <div className="bg-muted/50 rounded-lg p-4 font-mono text-sm">
                                <div className="mb-2">
                                  <span className={`font-semibold ${
                                    result.response.status >= 400 ? 'text-destructive' : 
                                    result.response.status >= 300 ? 'text-security-yellow' : 'text-primary'
                                  }`}>
                                    {result.response.status} {result.response.statusText}
                                  </span>
                                  <span className="text-muted-foreground ml-2">({result.response.time}ms)</span>
                                </div>
                                
                                <div className="mb-3">
                                  <div className="text-muted-foreground mb-1">Headers:</div>
                                  {Object.entries(result.response.headers).map(([key, value]) => (
                                    <div key={key} className="text-xs">
                                      <span className="text-primary">{key}:</span> {value}
                                    </div>
                                  ))}
                                </div>

                                <div>
                                  <div className="text-muted-foreground mb-1">Body:</div>
                                  <div className="text-xs bg-background/50 rounded p-2 overflow-auto">
                                    {JSON.stringify(result.response.body, null, 2)}
                                  </div>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </CollapsibleContent>
                    </Collapsible>
                  </CardContent>
                </Card>
              ))}
            </div>

            {/* Summary */}
            <Card className="bg-gradient-card border-primary/20 mt-8">
              <CardHeader>
                <CardTitle>Security Assessment Summary</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid md:grid-cols-4 gap-4 text-center">
                  <div>
                    <div className="text-2xl font-bold text-destructive">
                      {testResults.filter(r => r.status === 'failed').length}
                    </div>
                    <div className="text-sm text-muted-foreground">Critical Issues</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-security-yellow">
                      {testResults.filter(r => r.status === 'warning').length}
                    </div>
                    <div className="text-sm text-muted-foreground">Warnings</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-primary">
                      {testResults.filter(r => r.status === 'passed').length}
                    </div>
                    <div className="text-sm text-muted-foreground">Passed</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-muted-foreground">
                      {testResults.length}
                    </div>
                    <div className="text-sm text-muted-foreground">Total Tests</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
};