import { useState } from "react";
import { Terminal, Play, Shield, AlertTriangle, CheckCircle, Copy, Eye, ChevronDown, ChevronUp, GripVertical, Move3D, Download, Globe, Edit3, Plus, X } from "lucide-react";
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';
import { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType } from 'docx';
import JSZip from 'jszip';
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
  const [selectedResult, setSelectedResult] = useState<TestResult | null>(null);
  const [sslVerify, setSslVerify] = useState(true);
  const [originalRequest, setOriginalRequest] = useState<any>(null);
  const [originalResponse, setOriginalResponse] = useState<any>(null);
  const [editableHeaders, setEditableHeaders] = useState<Record<string, string>>({});
  const [newHeaderKey, setNewHeaderKey] = useState("");
  const [newHeaderValue, setNewHeaderValue] = useState("");
  const [exportFormat, setExportFormat] = useState<'pdf' | 'docx' | 'zip'>('pdf');
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
    
    // Get all current headers
    const allHeaders = { ...parsedCurl.headers, ...editableHeaders };
    
    // Rebuild the curl command with updated headers
    let updatedCurl = `curl -X ${parsedCurl.method} '${parsedCurl.url}'`;
    
    // Add all headers
    const validHeaders = Object.entries(allHeaders)
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
    setEditableHeaders(prev => {
      const updated = { ...prev };
      delete updated[key];
      return updated;
    });
    updateCurlFromHeaders();
  };

  const updateHeader = (key: string, value: string) => {
    setEditableHeaders(prev => ({
      ...prev,
      [key]: value
    }));
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
    
    // Initialize editable headers with parsed headers
    setEditableHeaders(parsed.headers);
    
    // Store original request and simulate response
    setOriginalRequest({
      method: parsed.method,
      url: parsed.url,
      headers: parsed.headers,
      body: parsed.body,
      sslVerify: sslVerify
    });
    
    setOriginalResponse({
      status: 200,
      statusText: 'OK',
      headers: {
        'Content-Type': 'application/json',
        'X-Response-Time': '125ms',
        'Server': 'nginx/1.18.0'
      },
      body: { success: true, message: 'Original request successful' },
      time: 125
    });
    
    // Simulate progressive testing
    const mockResults: TestResult[] = [
      {
        id: 'test1',
        name: 'Authentication Testing',
        status: 'failed',
        description: 'Bearer token authentication detected',
        details: ['Testing requests without Authorization header', 'Testing with malformed tokens'],
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
        id: 'test2',
        name: 'Input Validation Testing',
        status: 'warning',
        description: 'Testing SQL injection in parameters',
        details: ['Testing SQL injection payloads', 'Checking parameter validation'],
        severity: 'Medium',
        request: { ...parsed, body: { ...parsed.body, malicious: "'; DROP TABLE users; --" } },
        response: {
          status: 400,
          statusText: 'Bad Request',
          headers: { 'Content-Type': 'application/json' },
          body: { error: 'Invalid input detected' },
          time: 200
        }
      }
    ];

    // Simulate progressive analysis
    for (let i = 0; i < mockResults.length; i++) {
      setCurrentTest(`Testing ${mockResults[i].name}...`);
      setAnalysisProgress((i + 1) / mockResults.length * 100);
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    setTestResults(mockResults);
    setIsAnalyzing(false);
    setCurrentTest("");
    
    toast({
      title: "Analysis Complete",
      description: `Found ${mockResults.filter(r => r.status === 'failed').length} critical issues`,
    });
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
              <h3 className="text-sm font-medium mb-3 flex items-center gap-2">
                <Shield className="w-4 h-4" />
                Select Vulnerabilities to Test
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {vulnerabilityOptions.map((vuln) => (
                  <div key={vuln.id} className="flex items-center space-x-2">
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
                    <label htmlFor={vuln.id} className="text-sm font-medium cursor-pointer">
                      {vuln.name}
                    </label>
                    <Badge variant="outline" className="text-xs">
                      {vuln.category}
                    </Badge>
                  </div>
                ))}
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
                        onBlur={() => updateCurlFromHeaders()}
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

        {/* Test Results */}
        {testResults.length > 0 && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold">Security Test Results</h2>
              <div className="flex items-center gap-3">
                <Select value={exportFormat} onValueChange={(value: 'pdf' | 'docx' | 'zip') => setExportFormat(value)}>
                  <SelectTrigger className="w-32">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pdf">PDF</SelectItem>
                    <SelectItem value="docx">DOCX</SelectItem>
                    <SelectItem value="zip">ZIP</SelectItem>
                  </SelectContent>
                </Select>
                <Button
                  onClick={() => {}}
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
                <Card key={result.id} className="bg-gradient-card border-primary/20">
                  <CardHeader>
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          {getStatusIcon(result.status)}
                          <h3 className="text-lg font-semibold">{result.name}</h3>
                          <Badge variant={result.status === 'failed' ? 'destructive' : result.status === 'warning' ? 'secondary' : 'default'}>
                            {result.status}
                          </Badge>
                        </div>
                        <p className="text-muted-foreground">{result.description}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => copyTestCurl(result.request)}
                          className="flex items-center gap-2"
                        >
                          <Copy className="w-4 h-4" />
                          Copy cURL
                        </Button>
                        <Badge variant={getSeverityColor(result.severity) as any}>
                          {result.severity}
                        </Badge>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <h4 className="font-semibold text-sm">Test Details:</h4>
                      <ul className="list-disc list-inside text-sm text-muted-foreground space-y-1">
                        {result.details.map((detail, index) => (
                          <li key={index}>{detail}</li>
                        ))}
                      </ul>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};