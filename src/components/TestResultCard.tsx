import { useState } from "react";
import { AlertTriangle, CheckCircle, Shield, Copy, ChevronDown, ChevronUp, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { useToast } from "@/hooks/use-toast";

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

interface TestResultCardProps {
  result: TestResult;
  isExpanded: boolean;
  onToggleExpanded: (resultId: string) => void;
}

export const TestResultCard = ({ result, isExpanded, onToggleExpanded }: TestResultCardProps) => {
  const { toast } = useToast();

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
    <Card className="bg-gradient-card border-primary/20">
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
            <Button
              variant="ghost"
              size="sm"
              onClick={() => onToggleExpanded(result.id)}
              className="flex items-center gap-2"
            >
              {isExpanded ? (
                <ChevronUp className="w-4 h-4" />
              ) : (
                <ChevronDown className="w-4 h-4" />
              )}
              Details
            </Button>
            <Badge variant={getSeverityColor(result.severity) as any}>
              {result.severity}
            </Badge>
          </div>
        </div>
      </CardHeader>
      
      <Collapsible open={isExpanded}>
        <CollapsibleContent>
          <CardContent className="space-y-4 border-t">
            {/* Test Details */}
            <div className="space-y-2">
              <h4 className="font-semibold text-sm">Test Details:</h4>
              <ul className="list-disc list-inside text-sm text-muted-foreground space-y-1">
                {result.details.map((detail, index) => (
                  <li key={index}>{detail}</li>
                ))}
              </ul>
            </div>

            {/* Request Details */}
            <div className="space-y-2">
              <h4 className="font-semibold text-sm">Request Details:</h4>
              <div className="p-3 rounded-lg bg-muted/30 border">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Method & URL</p>
                    <p className="font-mono text-sm">{result.request.method} {result.request.url}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Headers</p>
                    <div className="space-y-1">
                      {Object.entries(result.request.headers).map(([key, value]) => (
                        <p key={key} className="font-mono text-xs">
                          <span className="text-muted-foreground">{key}:</span> {String(value)}
                        </p>
                      ))}
                    </div>
                  </div>
                </div>
                {result.request.body && (
                  <div className="mt-3">
                    <p className="text-xs text-muted-foreground mb-1">Request Body</p>
                    <pre className="text-xs font-mono bg-background/50 p-2 rounded border overflow-auto max-h-32">
                      {typeof result.request.body === 'string' 
                        ? result.request.body 
                        : JSON.stringify(result.request.body, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>

            {/* Response Details */}
            <div className="space-y-2">
              <h4 className="font-semibold text-sm">Response Details:</h4>
              <div className="p-3 rounded-lg bg-muted/30 border">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Status</p>
                    <div className="flex items-center gap-2">
                      <Badge variant={result.response.status >= 400 ? "destructive" : "default"}>
                        {result.response.status}
                      </Badge>
                      <span className="text-sm">{result.response.statusText}</span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      Response time: {result.response.time}ms
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Response Headers</p>
                    <div className="space-y-1">
                      {Object.entries(result.response.headers).map(([key, value]) => (
                        <p key={key} className="font-mono text-xs">
                          <span className="text-muted-foreground">{key}:</span> {String(value)}
                        </p>
                      ))}
                    </div>
                  </div>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Response Body</p>
                  <pre className="text-xs font-mono bg-background/50 p-2 rounded border overflow-auto max-h-32">
                    {typeof result.response.body === 'string' 
                      ? result.response.body 
                      : JSON.stringify(result.response.body, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          </CardContent>
        </CollapsibleContent>
      </Collapsible>
    </Card>
  );
};