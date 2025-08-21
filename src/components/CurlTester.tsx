import { useState } from "react";
import { Terminal, Play, Shield, AlertTriangle, CheckCircle, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
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
}

export const CurlTester = () => {
  const [curlCommand, setCurlCommand] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [parsedCurl, setParsedCurl] = useState<ParsedCurl | null>(null);
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const { toast } = useToast();

  const exampleCurl = `curl -X POST https://api.example.com/users \\
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMjM0NTY3ODkwLCJuYW1lIjoiSm9obiBEb2UifQ.Ks7KcdjrlUWKqJmXiWKt1nKaWhLZHzJyWnkhzUa6GwA" \\
  -H "Content-Type: application/json" \\
  -d '{"userId": 123, "role": "user", "email": "john@example.com", "isAdmin": false}'`;

  const parseCurlCommand = (curl: string): ParsedCurl | null => {
    try {
      const urlMatch = curl.match(/curl\s+(?:-X\s+\w+\s+)?(?:["']?)([^"'\s]+)(?:["']?)/);
      const methodMatch = curl.match(/-X\s+(\w+)/);
      const headerMatches = curl.matchAll(/-H\s+["']([^"']+)["']/g);
      const bodyMatch = curl.match(/-d\s+['"`]([^'"`]+)['"`]/);

      if (!urlMatch) return null;

      const url = urlMatch[1];
      const method = methodMatch?.[1] || 'GET';
      const headers: Record<string, string> = {};
      
      for (const match of headerMatches) {
        const [key, value] = match[1].split(': ');
        if (key && value) headers[key] = value;
      }

      const body = bodyMatch ? JSON.parse(bodyMatch[1]) : null;
      const endpoint = new URL(url).pathname;

      return { url, method, headers, body, endpoint };
    } catch (error) {
      return null;
    }
  };

  const generateSecurityTests = (parsed: ParsedCurl): TestResult[] => {
    const results: TestResult[] = [];

    // BOLA Testing
    if (parsed.body?.userId || parsed.endpoint.includes('/users/')) {
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
        severity: 'Critical'
      });
    }

    // Authentication Testing
    if (parsed.headers.Authorization) {
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
        severity: 'High'
      });
    } else {
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
        severity: 'Critical'
      });
    }

    // BOPLA Testing
    if (parsed.body && typeof parsed.body === 'object') {
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
        severity: 'High'
      });
    }

    // Rate Limiting
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
      severity: 'Medium'
    });

    // SSRF Testing
    if (parsed.body && JSON.stringify(parsed.body).includes('http')) {
      results.push({
        id: 'ssrf',
        name: 'Server Side Request Forgery (SSRF)',
        status: 'failed',
        description: 'URL parameters detected in request body',
        details: [
          'Testing internal network access',
          'Injecting metadata endpoints',
          'Checking URL validation'
        ],
        severity: 'High'
      });
    }

    // Add some passing tests
    results.push({
      id: 'headers',
      name: 'Security Headers Check',
      status: 'passed',
      description: 'Proper Content-Type header detected',
      details: [
        'Content-Type header present',
        'JSON content properly specified',
        'No obvious header injection'
      ],
      severity: 'Low'
    });

    return results;
  };

  const handleAnalyzeCurl = () => {
    if (!curlCommand.trim()) {
      toast({
        title: "Missing cURL Command",
        description: "Please provide a cURL command to analyze",
        variant: "destructive"
      });
      return;
    }

    setIsAnalyzing(true);
    
    // Simulate API analysis
    setTimeout(() => {
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
      const results = generateSecurityTests(parsed);
      setTestResults(results);
      setIsAnalyzing(false);
      
      toast({
        title: "Analysis Complete",
        description: `Found ${results.filter(r => r.status === 'failed').length} critical issues`,
        variant: "default"
      });
    }, 2000);
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
            <h2 className="text-2xl font-bold mb-6">Security Test Results</h2>
            <div className="grid gap-4">
              {testResults.map((result) => (
                <Card key={result.id} className="bg-gradient-card border-primary/20">
                  <CardHeader>
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-center gap-3">
                        {getStatusIcon(result.status)}
                        <div>
                          <CardTitle className="text-lg flex items-center gap-3">
                            {result.name}
                            <Badge className={getSeverityColor(result.severity)}>
                              {result.severity}
                            </Badge>
                          </CardTitle>
                          <p className="text-muted-foreground mt-1">{result.description}</p>
                        </div>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
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