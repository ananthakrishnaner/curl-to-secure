import { useState } from "react";
import { Terminal, Play, Shield, AlertTriangle, CheckCircle, Copy, Eye, ChevronDown, ChevronUp, GripVertical, Move3D, Download, Globe, Edit3, Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { generateTestPayloads } from "@/utils/testPayloads";
import { exportToPDF, exportToDocx, exportToZip, exportToMarkdown } from "@/utils/exportUtils";
import { TestResultCard } from "@/components/TestResultCard";
import { ScanProgress } from "@/components/ScanProgress";

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
  const [selectedVulnerabilities, setSelectedVulnerabilities] = useState<Set<string>>(new Set(['headers']));
  const [scanType, setScanType] = useState<'basic' | 'advanced' | 'custom'>('basic');
  const [customPayloads, setCustomPayloads] = useState("");
  const [draggedItem, setDraggedItem] = useState<TestResult | null>(null);
  const [selectedResult, setSelectedResult] = useState<TestResult | null>(null);
  const [sslVerify, setSslVerify] = useState(true);
  const [originalRequest, setOriginalRequest] = useState<any>(null);
  const [originalResponse, setOriginalResponse] = useState<any>(null);
  const [editableHeaders, setEditableHeaders] = useState<Record<string, string>>({});
  const [newHeaderKey, setNewHeaderKey] = useState("");
  const [newHeaderValue, setNewHeaderValue] = useState("");
  const [exportFormat, setExportFormat] = useState<'pdf' | 'docx' | 'zip' | 'markdown'>('pdf');
  const { toast } = useToast();

  const vulnerabilityOptions = [
    { id: 'bola', name: 'Broken Object Level Authorization (BOLA)', category: 'Authorization' },
    { id: 'auth', name: 'Authentication Testing', category: 'Authentication' },
    { id: 'bopla', name: 'Broken Object Property Level Authorization', category: 'Authorization' },
    { id: 'rate_limit', name: 'Rate Limiting Testing', category: 'Resource Management' },
    { id: 'input_validation', name: 'Input Validation Testing', category: 'Input Validation' },
    { id: 'ssrf', name: 'Server Side Request Forgery (SSRF)', category: 'Network Security' },
    { id: 'headers', name: 'Security Headers Check', category: 'Configuration' },
    { id: 'mass_assignment', name: 'Mass Assignment Testing', category: 'Input Validation' },
    { id: 'jwt_manipulation', name: 'JWT Token Manipulation', category: 'Authentication' },
    { id: 'nosql_injection', name: 'NoSQL Injection Testing', category: 'Input Validation' },
    { id: 'xml_injection', name: 'XML External Entity (XXE) Testing', category: 'Input Validation' },
    { id: 'cors_misconfiguration', name: 'CORS Misconfiguration Testing', category: 'Configuration' },
    { id: 'http_method_override', name: 'HTTP Method Override Testing', category: 'Configuration' }
  ];

  const exampleCurl = `curl -X POST https://api.example.com/users \\
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMjM0NTY3ODkwLCJuYW1lIjoiSm9obiBEb2UifQ.Ks7KcdjrlUWKqJmXiWKt1nKaWhLZHzJyWnkhzUa6GwA" \\
  -H "Content-Type: application/json" \\
  -H "User-Agent: MyApp/1.0" \\
  --data-raw '{"userId": 123, "role": "user", "email": "john@example.com", "isAdmin": false, "callbackUrl": "https://webhook.site/test"}'`;

  const parseCurlCommand = (curl: string): ParsedCurl | null => {
    try {
      console.log('🔍 Original cURL command:', curl);
      
      // Normalize the curl command - remove line breaks and extra spaces
      const normalizedCurl = curl.replace(/\\\s*\n/g, ' ').replace(/\s+/g, ' ').trim();
      console.log('🔧 Normalized cURL:', normalizedCurl);
      
      // Extract URL - much more specific patterns
      let urlMatch = null;
      
      // Pattern 1: Look for http/https URLs anywhere in the command
      urlMatch = normalizedCurl.match(/(https?:\/\/[^\s'"]+)/);
      
      if (!urlMatch) {
        // Pattern 2: Look for quoted URLs
        urlMatch = normalizedCurl.match(/['"`](https?:\/\/[^'"`]+)['"`]/);
      }
      
      if (!urlMatch) {
        // Pattern 3: Look for URL after curl but before flags
        urlMatch = normalizedCurl.match(/curl\s+([^\s-]+)/);
      }
      
      if (!urlMatch) {
        // Pattern 4: Look for URL after method specification
        urlMatch = normalizedCurl.match(/-X\s+\w+\s+['"`]?([^'"`\s]+)['"`]?/);
      }
      
      console.log('🎯 URL matches:', urlMatch);

      if (!urlMatch) {
        console.log('❌ No URL found in cURL command');
        return null;
      }

      // Clean the URL of any surrounding quotes
      let url = urlMatch[1].replace(/^['"]|['"]$/g, '');
      
      // Ensure URL has protocol
      if (!url.match(/^https?:\/\//)) {
        url = 'https://' + url;
      }
      console.log('🌐 Final URL:', url);
      
      // Extract method
      const methodMatch = normalizedCurl.match(/-X\s+([A-Z]+)/i) || normalizedCurl.match(/--request\s+([A-Z]+)/i);
      const method = methodMatch?.[1]?.toUpperCase() || 'GET';
      console.log('📋 Method:', method);
      
      // Extract headers - improved patterns
      const headerMatches = [];
      
      // Pattern 1: -H "Header: Value"
      const headerPattern1 = [...normalizedCurl.matchAll(/-H\s+"([^"]+)"/g)];
      headerMatches.push(...headerPattern1);
      
      // Pattern 2: -H 'Header: Value'
      const headerPattern2 = [...normalizedCurl.matchAll(/-H\s+'([^']+)'/g)];
      headerMatches.push(...headerPattern2);
      
      // Pattern 3: --header "Header: Value"
      const headerPattern3 = [...normalizedCurl.matchAll(/--header\s+"([^"]+)"/g)];
      headerMatches.push(...headerPattern3);
      
      // Pattern 4: --header 'Header: Value'
      const headerPattern4 = [...normalizedCurl.matchAll(/--header\s+'([^']+)'/g)];
      headerMatches.push(...headerPattern4);
      
      console.log('📝 Header matches found:', headerMatches.length);
      console.log('📝 Header content:', headerMatches.map(m => m[1]));
      
      // Extract body data - handle multiple formats and multiline JSON
      let bodyMatch = null;
      
      // Better body parsing - find the -d or --data flag and capture everything until next flag or end
      const dataFlagMatch = normalizedCurl.match(/-d\s+(['"`])((?:(?!\1).|\1(?!\s+-))*)\1/);
      if (dataFlagMatch) {
        bodyMatch = [dataFlagMatch[0], dataFlagMatch[2]];
      } else {
        // Fallback to simpler patterns
        bodyMatch = 
          normalizedCurl.match(/-d\s+'([^']+)'/) ||
          normalizedCurl.match(/-d\s+"([^"]+)"/) ||
          normalizedCurl.match(/-d\s+\`([^\`]+)\`/) ||
          normalizedCurl.match(/--data\s+'([^']+)'/) ||
          normalizedCurl.match(/--data\s+"([^"]+)"/) ||
          normalizedCurl.match(/--data-raw\s+'([^']+)'/) ||
          normalizedCurl.match(/--data-raw\s+"([^"]+)"/);
      }
      
      console.log('📦 Body match:', bodyMatch ? bodyMatch[1] : 'No body found');

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
      console.log('📋 Final headers:', headers);

      // Process body
      let body = null;
      if (bodyMatch) {
        try {
          body = JSON.parse(bodyMatch[1]);
          console.log('✅ Parsed JSON body:', body);
        } catch {
          // If not valid JSON, store as string
          body = bodyMatch[1];
          console.log('📄 String body:', body);
        }
      }

      const endpoint = new URL(url).pathname;
      const result = { url, method, headers, body, endpoint };
      console.log('🎉 Final parsed result:', result);
      
      return result;
    } catch (error) {
      console.error('❌ cURL parsing error:', error);
      return null;
    }
  };

  const generateCurlFromRequest = (request: any) => {
    let curlCmd = `curl -X ${request.method}`;
    
    // Add URL (with proper quoting if it contains special characters)
    curlCmd += ` '${request.url}'`;
    
    // Add headers
    if (request.headers && Object.keys(request.headers).length > 0) {
      Object.entries(request.headers).forEach(([key, value]) => {
        curlCmd += ` \\\n  -H '${key}: ${value}'`;
      });
    }
    
    // Add body if present
    if (request.body) {
      const bodyStr = typeof request.body === 'string' ? request.body : JSON.stringify(request.body);
      curlCmd += ` \\\n  -d '${bodyStr}'`;
    }
    
    return curlCmd;
  };

  const copyTestCurl = async (request: any) => {
    const curlCommand = generateCurlFromRequest(request);
    try {
      await navigator.clipboard.writeText(curlCommand);
      toast({
        title: "Copied to Clipboard",
        description: "cURL command has been copied",
      });
    } catch (error) {
      toast({
        title: "Copy Failed",
        description: "Could not copy to clipboard",
        variant: "destructive"
      });
    }
  };

  const updateParsedUrl = (newUrl: string) => {
    if (parsedCurl) {
      setParsedCurl({ ...parsedCurl, url: newUrl });
    }
  };

  const updateParsedMethod = (newMethod: string) => {
    if (parsedCurl) {
      setParsedCurl({ ...parsedCurl, method: newMethod.toUpperCase() });
    }
  };

  const updateParsedBody = (newBody: string) => {
    if (parsedCurl) {
      try {
        const parsed = JSON.parse(newBody);
        setParsedCurl({ ...parsedCurl, body: parsed });
      } catch {
        setParsedCurl({ ...parsedCurl, body: newBody });
      }
    }
  };

  const updateCurlFromHeaders = () => {
    if (!parsedCurl) return;
    
    // Update the parsedCurl with the current editable headers
    const updatedParsedCurl = {
      ...parsedCurl,
      headers: { ...editableHeaders }
    };
    setParsedCurl(updatedParsedCurl);
    
    // Rebuild the curl command with updated headers
    let updatedCurl = `curl -X ${parsedCurl.method} '${parsedCurl.url}'`;
    
    // Add all headers
    const validHeaders = Object.entries(editableHeaders)
      .filter(([key, value]) => key.trim() !== '' && value.trim() !== '');
    
    if (validHeaders.length > 0) {
      const headerLines = validHeaders
        .map(([key, value]) => `  -H '${key}: ${value}'`)
        .join(' \\\n');
      
      updatedCurl += ' \\\n' + headerLines;
    }
    
    // Add body if present
    if (parsedCurl.body) {
      const bodyStr = typeof parsedCurl.body === 'string' ? parsedCurl.body : JSON.stringify(parsedCurl.body);
      updatedCurl += ` \\\n  -d '${bodyStr}'`;
    }
    
    setCurlCommand(updatedCurl);
    
    toast({
      title: "cURL Updated",
      description: "The cURL command has been updated with your changes",
    });
  };

  const addNewHeader = () => {
    if (newHeaderKey.trim() && newHeaderValue.trim()) {
      setEditableHeaders(prev => ({
        ...prev,
        [newHeaderKey.trim()]: newHeaderValue.trim()
      }));
      setNewHeaderKey("");
      setNewHeaderValue("");
      updateCurlFromHeaders();
    }
  };

  const removeHeader = (key: string) => {
    if (parsedCurl) {
      // Remove from parsed curl headers
      const updatedHeaders = { ...parsedCurl.headers };
      delete updatedHeaders[key];
      setParsedCurl({ ...parsedCurl, headers: updatedHeaders });
    }
    
    // Remove from editable headers
    setEditableHeaders(prev => {
      const updated = { ...prev };
      delete updated[key];
      return updated;
    });
    
    // Update curl command after removal
    setTimeout(() => updateCurlFromHeaders(), 100);
  };

  const updateHeader = (key: string, value: string) => {
    setEditableHeaders(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const triggerCurlUpdate = () => {
    setTimeout(() => updateCurlFromHeaders(), 300);
  };

  const makeHttpRequest = async (request: any): Promise<any> => {
    const startTime = Date.now();
    
    try {
      const fetchOptions: RequestInit = {
        method: request.method,
        headers: request.headers,
        mode: 'cors'
      };
      
      if (request.body && (request.method === 'POST' || request.method === 'PUT' || request.method === 'PATCH')) {
        fetchOptions.body = typeof request.body === 'string' ? request.body : JSON.stringify(request.body);
      }
      
      const response = await fetch(request.url, fetchOptions);
      const endTime = Date.now();
      
      let responseBody;
      const contentType = response.headers.get('Content-Type') || '';
      
      if (contentType.includes('application/json')) {
        try {
          responseBody = await response.json();
        } catch {
          responseBody = await response.text();
        }
      } else {
        responseBody = await response.text();
      }
      
      // Convert headers to object
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });
      
      return {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
        body: responseBody,
        time: endTime - startTime
      };
    } catch (error) {
      const endTime = Date.now();
      return {
        status: 0,
        statusText: 'Network Error',
        headers: {},
        body: { error: error instanceof Error ? error.message : 'Unknown error' },
        time: endTime - startTime
      };
    }
  };

  const analyzeTestCase = (originalResponse: any, testResponse: any, testName: string): 'passed' | 'failed' | 'warning' => {
    // Authentication tests
    if (testName.includes('Authentication')) {
      if (testResponse.status === 401 || testResponse.status === 403) {
        return 'passed'; // Good - authentication is working
      }
      return 'failed'; // Bad - authentication bypass possible
    }
    
    // BOLA tests
    if (testName.includes('BOLA') || testName.includes('Authorization')) {
      if (testResponse.status === 403 || testResponse.status === 404) {
        return 'passed'; // Good - authorization is working
      }
      if (testResponse.status === 200) {
        return 'failed'; // Bad - potential BOLA vulnerability
      }
      return 'warning';
    }
    
    // Rate limiting tests
    if (testName.includes('Rate Limiting')) {
      if (testResponse.status === 429) {
        return 'passed'; // Good - rate limiting is working
      }
      return 'failed'; // Bad - no rate limiting
    }
    
    // Input validation tests
    if (testName.includes('Input Validation') || testName.includes('injection')) {
      if (testResponse.status === 400 || testResponse.status === 422) {
        return 'passed'; // Good - input validation is working
      }
      if (testResponse.status === 200) {
        return 'failed'; // Bad - potential injection vulnerability
      }
      return 'warning';
    }
    
    // Security headers
    if (testName.includes('Headers')) {
      const hasSecurityHeaders = Object.keys(testResponse.headers).some(header => 
        ['x-frame-options', 'content-security-policy', 'x-content-type-options', 'strict-transport-security']
          .includes(header.toLowerCase())
      );
      return hasSecurityHeaders ? 'passed' : 'warning';
    }
    
    // Default analysis
    if (testResponse.status >= 400) {
      return 'passed'; // Server rejected malicious request
    }
    if (testResponse.status === 200) {
      return 'warning'; // Request succeeded - might be vulnerable
    }
    return 'warning';
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
    setEditableHeaders(parsed.headers);
    
    try {
      // First, make the original request
      setCurrentTest("Making original request...");
      setAnalysisProgress(5);
      
      const originalRequest = {
        method: parsed.method,
        url: parsed.url,
        headers: parsed.headers,
        body: parsed.body,
        sslVerify: sslVerify
      };
      
      const originalResponse = await makeHttpRequest(originalRequest);
      setOriginalRequest(originalRequest);
      setOriginalResponse(originalResponse);
      
      // Generate test payloads based on scan type and selected vulnerabilities
      console.log('🎯 Selected vulnerabilities:', Array.from(selectedVulnerabilities));
      console.log('📊 Scan type:', scanType);
      const testTemplates = generateTestPayloads(parsed, scanType, selectedVulnerabilities, customPayloads);
      console.log('🧪 Generated test templates:', testTemplates.length, testTemplates.map(t => t.name));
      const actualTestResults: TestResult[] = [];
      
      // Execute each test
      for (let i = 0; i < testTemplates.length; i++) {
        const testTemplate = testTemplates[i];
        setCurrentTest(`Testing ${testTemplate.name}...`);
        setAnalysisProgress(((i + 1) / testTemplates.length) * 95 + 5);
        
        // Make the actual HTTP request for this test
        const testResponse = await makeHttpRequest(testTemplate.request);
        
        // Analyze the response to determine if it passed/failed
        const status = analyzeTestCase(originalResponse, testResponse, testTemplate.name);
        
        const actualResult: TestResult = {
          ...testTemplate,
          status,
          response: testResponse
        };
        
        actualTestResults.push(actualResult);
        await new Promise(resolve => setTimeout(resolve, 300)); // Small delay between requests
      }
      
      setTestResults(actualTestResults);
      setAnalysisProgress(100);
      
      const failedTests = actualTestResults.filter(r => r.status === 'failed').length;
      const warningTests = actualTestResults.filter(r => r.status === 'warning').length;
      const passedTests = actualTestResults.filter(r => r.status === 'passed').length;
      
      toast({
        title: "Analysis Complete",
        description: `${scanType.charAt(0).toUpperCase() + scanType.slice(1)} scan: ${passedTests} passed, ${failedTests} failed, ${warningTests} warnings`,
      });
      
    } catch (error) {
      toast({
        title: "Analysis Failed",
        description: error instanceof Error ? error.message : "Unknown error occurred",
        variant: "destructive"
      });
    } finally {
      setIsAnalyzing(false);
      setCurrentTest("");
    }
  };

  const copyExample = () => {
    setCurlCommand(exampleCurl);
    toast({
      title: "Example Loaded",
      description: "Example cURL command has been loaded",
    });
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'passed': return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'failed': return <AlertTriangle className="w-4 h-4 text-red-500" />;
      case 'warning': return <Shield className="w-4 h-4 text-yellow-500" />;
      default: return <Shield className="w-4 h-4" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'destructive';
      case 'High': return 'destructive';
      case 'Medium': return 'secondary';
      case 'Low': return 'default';
      default: return 'default';
    }
  };

  const toggleResultExpanded = (resultId: string) => {
    const newExpanded = new Set(expandedResults);
    if (newExpanded.has(resultId)) {
      newExpanded.delete(resultId);
    } else {
      newExpanded.add(resultId);
    }
    setExpandedResults(newExpanded);
  };

  const exportResults = async () => {
    try {
      console.log('🚀 Starting export...', { exportFormat, testResultsLength: testResults.length });
      
      if (exportFormat === 'pdf') {
        await exportToPDF(testResults, originalRequest, originalResponse);
      } else if (exportFormat === 'docx') {
        console.log('📄 Starting DOCX export...');
        await exportToDocx(testResults, originalRequest, originalResponse);
        console.log('✅ DOCX export completed');
      } else if (exportFormat === 'zip') {
        await exportToZip(testResults, originalRequest, originalResponse);
      } else if (exportFormat === 'markdown') {
        await exportToMarkdown(testResults, originalRequest, originalResponse);
      }
      
      toast({
        title: "Export Successful",
        description: `Security test results exported as ${exportFormat.toUpperCase()}`,
      });
    } catch (error) {
      console.error('❌ Export failed:', error);
      toast({
        title: "Export Failed",
        description: error instanceof Error ? error.message : "Could not export the results",
        variant: "destructive"
      });
    }
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
            <div className="bg-muted/20 p-4 rounded-lg border">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-medium flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  Select Vulnerabilities to Test
                </h3>
                <Badge variant="secondary" className="text-xs">
                  {selectedVulnerabilities.size} selected
                </Badge>
              </div>
              
              {/* Quick selection buttons */}
              <div className="flex gap-2 mb-4">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setSelectedVulnerabilities(new Set(vulnerabilityOptions.map(v => v.id)))}
                  className="text-xs"
                >
                  Select All
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setSelectedVulnerabilities(new Set())}
                  className="text-xs"
                >
                  Clear All
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setSelectedVulnerabilities(new Set(['bola', 'auth', 'input_validation', 'headers']))}
                  className="text-xs"
                >
                  Essential Only
                </Button>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {vulnerabilityOptions.map((vuln) => (
                  <div key={vuln.id} className={`flex items-center space-x-2 p-2 rounded-md border transition-all duration-200 ${
                    selectedVulnerabilities.has(vuln.id) 
                      ? 'bg-primary/10 border-primary/30' 
                      : 'bg-background/50 border-border/50 hover:border-border'
                  }`}>
                    <Checkbox
                      id={vuln.id}
                      checked={selectedVulnerabilities.has(vuln.id)}
                      onCheckedChange={(checked) => {
                        const newSelected = new Set(selectedVulnerabilities);
                        if (checked) {
                          newSelected.add(vuln.id);
                        } else {
                          newSelected.delete(vuln.id);
                        }
                        setSelectedVulnerabilities(newSelected);
                      }}
                    />
                    <label htmlFor={vuln.id} className="text-sm font-medium cursor-pointer flex-1">
                      {vuln.name}
                    </label>
                    <Badge variant="outline" className="text-xs">
                      {vuln.category}
                    </Badge>
                  </div>
                ))}
              </div>
              
              {/* Selected vulnerabilities summary */}
              {selectedVulnerabilities.size > 0 && (
                <div className="mt-3 p-2 bg-primary/5 rounded-md border border-primary/20">
                  <p className="text-xs text-muted-foreground mb-1">Selected tests:</p>
                  <div className="flex flex-wrap gap-1">
                    {Array.from(selectedVulnerabilities).map(vulnId => {
                      const vuln = vulnerabilityOptions.find(v => v.id === vulnId);
                      return vuln ? (
                        <Badge key={vulnId} variant="secondary" className="text-xs">
                          {vuln.name.split(' ')[0]}
                        </Badge>
                      ) : null;
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Scan Type Selection */}
            <div className="bg-muted/20 p-4 rounded-lg border">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-medium flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  Scan Type
                </h3>
                <Badge variant={scanType === 'advanced' ? 'default' : 'secondary'} className="text-xs">
                  {scanType.charAt(0).toUpperCase() + scanType.slice(1)}
                </Badge>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
                <div 
                  className={`p-3 rounded-md border cursor-pointer transition-all duration-200 ${
                    scanType === 'basic' 
                      ? 'bg-primary/10 border-primary ring-2 ring-primary/20' 
                      : 'bg-background/50 border-border hover:border-border/80'
                  }`}
                  onClick={() => setScanType('basic')}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="font-medium text-sm">Basic Scan</div>
                      <div className="text-xs text-muted-foreground mt-1">5-7 essential security tests</div>
                      <div className="text-xs text-muted-foreground">Faster execution</div>
                    </div>
                    <div className={`w-3 h-3 rounded-full border-2 ${
                      scanType === 'basic' ? 'bg-primary border-primary' : 'border-border'
                    }`} />
                  </div>
                </div>
                
                <div 
                  className={`p-3 rounded-md border cursor-pointer transition-all duration-200 ${
                    scanType === 'advanced' 
                      ? 'bg-primary/10 border-primary ring-2 ring-primary/20' 
                      : 'bg-background/50 border-border hover:border-border/80'
                  }`}
                  onClick={() => setScanType('advanced')}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="font-medium text-sm">Advanced Scan</div>
                      <div className="text-xs text-muted-foreground mt-1">12-15 comprehensive tests</div>
                      <div className="text-xs text-muted-foreground">Thorough analysis</div>
                    </div>
                    <div className={`w-3 h-3 rounded-full border-2 ${
                      scanType === 'advanced' ? 'bg-primary border-primary' : 'border-border'
                    }`} />
                  </div>
                </div>

                <div 
                  className={`p-3 rounded-md border cursor-pointer transition-all duration-200 ${
                    scanType === 'custom' 
                      ? 'bg-primary/10 border-primary ring-2 ring-primary/20' 
                      : 'bg-background/50 border-border hover:border-border/80'
                  }`}
                  onClick={() => setScanType('custom')}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="font-medium text-sm">Custom Scan</div>
                      <div className="text-xs text-muted-foreground mt-1">User-defined payloads</div>
                      <div className="text-xs text-muted-foreground">Custom security tests</div>
                    </div>
                    <div className={`w-3 h-3 rounded-full border-2 ${
                      scanType === 'custom' ? 'bg-primary border-primary' : 'border-border'
                    }`} />
                  </div>
                </div>
              </div>

              {scanType === 'custom' && (
                <div className="space-y-3 mb-3">
                  <label className="block text-sm font-medium">
                    Custom Payloads (one per line)
                  </label>
                  <Textarea
                    placeholder={`Enter your custom payloads here, one per line:
'; DROP TABLE users; --
<script>alert('XSS')</script>
../../etc/passwd
{"$ne": null}`}
                    value={customPayloads}
                    onChange={(e) => setCustomPayloads(e.target.value)}
                    className="min-h-[120px] font-mono text-sm"
                  />
                  <p className="text-sm text-muted-foreground">
                    These payloads will be tested against all input parameters in your request
                  </p>
                </div>
              )}
              
              {/* Scan type info */}
              <div className="p-2 bg-muted/30 rounded-md">
                <p className="text-xs text-muted-foreground">
                  {scanType === 'basic' 
                    ? 'Basic scan focuses on common vulnerabilities and executes faster.' 
                    : scanType === 'advanced'
                      ? 'Advanced scan includes comprehensive testing with more payloads and edge cases.'
                      : 'Custom scan allows you to test with your own security payloads.'
                  }
                </p>
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <input
                id="ssl-verify"
                type="checkbox"
                checked={sslVerify}
                onChange={(e) => setSslVerify(e.target.checked)}
                className="rounded border-gray-300"
              />
              <label htmlFor="ssl-verify" className="text-sm font-medium">
                SSL Verify
              </label>
            </div>
            
            <Button 
              onClick={handleAnalyzeCurl}
              disabled={isAnalyzing}
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

        {/* Parsed Request Display */}
        {parsedCurl && (
          <Card className="bg-gradient-card border-primary/20 mb-8">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Eye className="w-5 h-5" />
                Parsed Request Details
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Request Summary - Make Editable */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-lg bg-muted/50 border">
                  <h4 className="font-semibold text-sm text-muted-foreground mb-2">Method</h4>
                  <Select value={parsedCurl.method} onValueChange={updateParsedMethod}>
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="GET">GET</SelectItem>
                      <SelectItem value="POST">POST</SelectItem>
                      <SelectItem value="PUT">PUT</SelectItem>
                      <SelectItem value="DELETE">DELETE</SelectItem>
                      <SelectItem value="PATCH">PATCH</SelectItem>
                      <SelectItem value="HEAD">HEAD</SelectItem>
                      <SelectItem value="OPTIONS">OPTIONS</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="p-4 rounded-lg bg-muted/50 border col-span-2">
                  <h4 className="font-semibold text-sm text-muted-foreground mb-2">URL</h4>
                  <Input
                    value={parsedCurl.url}
                    onChange={(e) => updateParsedUrl(e.target.value)}
                    className="font-mono text-sm"
                    placeholder="Enter URL"
                  />
                </div>
              </div>

              {/* Headers Editor */}
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="font-semibold text-primary">Headers</h4>
                  <Button 
                    variant="outline" 
                    size="sm" 
                    onClick={() => updateCurlFromHeaders()}
                  >
                    <Copy className="w-4 h-4 mr-2" />
                    Update cURL
                  </Button>
                </div>
                
                <div className="space-y-3" data-screenshot="request">
                  {Object.entries(parsedCurl.headers)
                    .filter(([key, value]) => key && value) // Filter out empty entries
                    .map(([key, value]) => (
                    <div key={key} className="flex items-center gap-2 p-3 rounded-lg bg-muted/30 border">
                      <Input
                        value={key}
                        disabled
                        className="flex-1 font-mono text-sm bg-background/50"
                        placeholder="Header name"
                      />
                      <span className="text-muted-foreground font-mono">:</span>
                       <Input
                        value={editableHeaders[key] !== undefined ? editableHeaders[key] : value}
                        onChange={(e) => updateHeader(key, e.target.value)}
                        onBlur={triggerCurlUpdate}
                        className="flex-1 font-mono text-sm"
                        placeholder="Header value"
                      />
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => removeHeader(key)}
                        className="text-destructive"
                      >
                        <X className="w-4 h-4" />
                      </Button>
                    </div>
                  ))}
                  
                  {/* Add New Header */}
                  <div className="flex items-center gap-2 p-3 rounded-lg bg-muted/30 border border-dashed">
                    <Input
                      value={newHeaderKey}
                      onChange={(e) => setNewHeaderKey(e.target.value)}
                      placeholder="Header name"
                      className="flex-1 font-mono text-sm"
                    />
                    <span className="text-muted-foreground font-mono">:</span>
                    <Input
                      value={newHeaderValue}
                      onChange={(e) => setNewHeaderValue(e.target.value)}
                      placeholder="Header value"
                      className="flex-1 font-mono text-sm"
                      onKeyPress={(e) => e.key === 'Enter' && addNewHeader()}
                    />
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={addNewHeader}
                      disabled={!newHeaderKey.trim() || !newHeaderValue.trim()}
                    >
                      <Plus className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </div>

              {/* Request Body - Make Editable */}
              {parsedCurl.body !== null && (
                <div className="space-y-2">
                  <h4 className="font-semibold text-primary">Request Body</h4>
                  <Textarea
                    value={typeof parsedCurl.body === 'string' ? parsedCurl.body : JSON.stringify(parsedCurl.body, null, 2)}
                    onChange={(e) => updateParsedBody(e.target.value)}
                    className="font-mono text-sm min-h-32"
                    placeholder="Enter request body (JSON or text)"
                  />
                </div>
              )}

              {/* Original Response */}
              {originalResponse && (
                <div className="space-y-2">
                  <h4 className="font-semibold text-primary">Original Response</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4" data-screenshot="response">
                    <div className="p-4 rounded-lg bg-muted/50 border">
                      <h5 className="font-semibold text-sm text-muted-foreground mb-2">Status</h5>
                      <div className="flex items-center gap-2">
                        <Badge variant={originalResponse.status === 200 ? "default" : "destructive"}>
                          {originalResponse.status}
                        </Badge>
                        <span className="text-sm">{originalResponse.statusText}</span>
                      </div>
                      <p className="text-xs text-muted-foreground mt-2">
                        Response time: {originalResponse.time}ms
                      </p>
                    </div>
                    <div className="p-4 rounded-lg bg-muted/50 border">
                      <h5 className="font-semibold text-sm text-muted-foreground mb-2">Headers</h5>
                      <div className="space-y-1 text-xs font-mono">
                        {Object.entries(originalResponse.headers).map(([key, value]) => (
                          <div key={key}>
                            <span className="text-muted-foreground">{key}:</span> {String(value)}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                  <div className="p-4 rounded-lg bg-muted/50 border">
                    <h5 className="font-semibold text-sm text-muted-foreground mb-2">Response Body</h5>
                    <pre className="text-xs font-mono overflow-auto max-h-32">
                      {JSON.stringify(originalResponse.body, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Enhanced Scan Progress */}
        <ScanProgress 
          isScanning={isAnalyzing}
          progress={analysisProgress}
          currentTest={currentTest}
          scanType={scanType}
        />

        {/* Test Results */}
        {testResults.length > 0 && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold">Security Test Results</h2>
              <div className="flex items-center gap-3">
                <Select value={exportFormat} onValueChange={(value: 'pdf' | 'docx' | 'zip' | 'markdown') => setExportFormat(value)}>
                  <SelectTrigger className="w-32">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pdf">PDF</SelectItem>
                    <SelectItem value="docx">DOCX</SelectItem>
                    <SelectItem value="zip">ZIP</SelectItem>
                    <SelectItem value="markdown">Markdown</SelectItem>
                  </SelectContent>
                </Select>
                <Button
                  onClick={exportResults}
                  variant="outline"
                  className="flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  Export {exportFormat.toUpperCase()}
                </Button>
              </div>
            </div>
            
            <div className="grid gap-4">
              {testResults.map((result) => (
                <TestResultCard
                  key={result.id}
                  result={result}
                  isExpanded={expandedResults.has(result.id)}
                  onToggleExpanded={toggleResultExpanded}
                />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};