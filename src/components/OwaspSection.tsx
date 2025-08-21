import { Shield, AlertTriangle, Users, Key, Database, FileText, Search, Zap, Clock, Settings } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export const OwaspSection = () => {
  const owaspVulnerabilities = [
    {
      id: "API1:2023",
      name: "Broken Object Level Authorization (BOLA)",
      icon: Users,
      severity: "Critical",
      description: "Tests if users can access objects they shouldn't have permission to view or modify.",
      testingApproach: [
        "Identifies object IDs in URL paths and JSON bodies",
        "Generates test cases with manipulated IDs (increment/decrement)",
        "Tests access with different user tokens",
        "Validates response codes and data exposure"
      ],
      example: "Original: /api/users/123 → Test: /api/users/124, /api/users/1, /api/users/999"
    },
    {
      id: "API2:2023", 
      name: "Broken Authentication",
      icon: Key,
      severity: "Critical",
      description: "Tests authentication mechanisms for weaknesses and bypass opportunities.",
      testingApproach: [
        "Tests requests without authentication headers",
        "Validates token expiration and refresh mechanisms", 
        "Tests with malformed or tampered tokens",
        "Checks for authentication bypass techniques"
      ],
      example: "Remove Authorization header, test with expired tokens, modify JWT payload"
    },
    {
      id: "API3:2023",
      name: "Broken Object Property Level Authorization (BOPLA)", 
      icon: FileText,
      severity: "High",
      description: "Tests if sensitive object properties are properly protected.",
      testingApproach: [
        "Adds privileged fields to request JSON (isAdmin: true)",
        "Tests property-level access controls",
        "Validates response filtering for sensitive data",
        "Tests mass assignment vulnerabilities"
      ],
      example: "Add {\"isAdmin\": true, \"role\": \"admin\"} to original JSON payload"
    },
    {
      id: "API4:2023",
      name: "Unrestricted Resource Consumption",
      icon: Zap,
      severity: "High", 
      description: "Tests for rate limiting and resource consumption controls.",
      testingApproach: [
        "Sends burst of requests to test rate limiting",
        "Tests with large payload sizes",
        "Validates timeout and resource limits",
        "Tests async operation flooding"
      ],
      example: "Send 100 requests in 1 second, test with 10MB JSON payload"
    },
    {
      id: "API5:2023",
      name: "Broken Function Level Authorization (BFLA)",
      icon: Settings,
      severity: "High",
      description: "Tests if users can access functions outside their privilege level.",
      testingApproach: [
        "Maps available endpoints from base URL",
        "Tests administrative endpoints with user tokens",
        "Validates HTTP method restrictions", 
        "Tests endpoint enumeration"
      ],
      example: "Test /admin/users with user token, try DELETE when only GET allowed"
    },
    {
      id: "API6:2023",
      name: "Unrestricted Access to Sensitive Business Flows",
      icon: AlertTriangle,
      severity: "Medium",
      description: "Tests business logic and workflow restrictions.",
      testingApproach: [
        "Identifies business-critical endpoints",
        "Tests workflow bypass techniques",
        "Validates step-by-step business processes",
        "Tests concurrent access to sensitive flows"
      ],
      example: "Skip payment verification, access restricted business functions"
    },
    {
      id: "API7:2023", 
      name: "Server Side Request Forgery (SSRF)",
      icon: Search,
      severity: "High",
      description: "Tests for server-side request forgery vulnerabilities.",
      testingApproach: [
        "Identifies URL parameters in requests",
        "Injects internal network addresses",
        "Tests cloud metadata endpoints",
        "Validates URL filtering mechanisms"
      ],
      example: "Replace URL with http://169.254.169.254/metadata, localhost:8080"
    },
    {
      id: "API8:2023",
      name: "Security Misconfiguration", 
      icon: Shield,
      severity: "Medium",
      description: "Tests for common security misconfigurations.",
      testingApproach: [
        "Tests CORS configuration",
        "Validates security headers",
        "Tests error message disclosure",
        "Checks for debug information exposure"
      ],
      example: "Test CORS with malicious origins, analyze error responses"
    },
    {
      id: "API9:2023",
      name: "Improper Inventory Management",
      icon: Database,
      severity: "Medium", 
      description: "Tests for exposed API versions and endpoints.",
      testingApproach: [
        "Discovers API versions from base endpoint",
        "Tests deprecated API versions",
        "Maps undocumented endpoints",
        "Validates version-specific vulnerabilities"
      ],
      example: "Test /v1/, /v2/, /api/v1/, discover hidden endpoints"
    },
    {
      id: "API10:2023",
      name: "Unsafe Consumption of APIs",
      icon: Clock,
      severity: "Medium",
      description: "Tests how the API handles third-party integrations.",
      testingApproach: [
        "Identifies external API calls in responses",
        "Tests input validation for external data",
        "Validates third-party API integration security",
        "Tests for data leakage to external services"
      ],
      example: "Monitor outbound requests, test external API response handling"
    }
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical": return "bg-destructive text-destructive-foreground";
      case "High": return "bg-security-red text-white";
      case "Medium": return "bg-security-yellow text-black";
      default: return "bg-muted text-muted-foreground";
    }
  };

  return (
    <section className="py-24 bg-muted/30">
      <div className="container px-4">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold mb-6">
            <span className="bg-text-gradient bg-clip-text text-transparent">OWASP API Security</span> Top 10 Testing
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            GreenAPI automatically generates comprehensive tests for all OWASP API Security Top 10 vulnerabilities, 
            using only the information extracted from your single cURL command.
          </p>
        </div>

        <div className="grid gap-8">
          {owaspVulnerabilities.map((vuln, index) => (
            <Card key={vuln.id} className="bg-gradient-card border-primary/20 hover:shadow-elegant transition-all duration-300">
              <CardHeader>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-center gap-4">
                    <div className="w-12 h-12 bg-primary/20 rounded-lg flex items-center justify-center">
                      <vuln.icon className="w-6 h-6 text-primary" />
                    </div>
                    <div>
                      <CardTitle className="text-xl flex items-center gap-3">
                        {vuln.id} - {vuln.name}
                        <Badge className={getSeverityColor(vuln.severity)}>
                          {vuln.severity}
                        </Badge>
                      </CardTitle>
                      <p className="text-muted-foreground mt-2">{vuln.description}</p>
                    </div>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <h4 className="font-semibold mb-3 text-primary">Testing Approach</h4>
                    <ul className="space-y-2">
                      {vuln.testingApproach.map((approach, i) => (
                        <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                          <span className="text-primary mt-1">•</span>
                          {approach}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <h4 className="font-semibold mb-3 text-primary">Example Test</h4>
                    <div className="bg-muted/50 rounded-lg p-3 font-mono text-sm">
                      {vuln.example}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="mt-16 bg-gradient-card border border-primary/20 rounded-xl p-8 text-center">
          <h3 className="text-2xl font-bold mb-4">Comprehensive Coverage in Minutes</h3>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            What traditionally takes security experts hours or days to configure and execute, 
            GreenAPI accomplishes in minutes - all from a single cURL command.
          </p>
        </div>
      </div>
    </section>
  );
};