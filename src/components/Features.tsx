import { Code, Brain, Shield, BarChart3, FileSearch, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export const Features = () => {
  const features = [
    {
      icon: Code,
      title: "Advanced cURL Parser",
      description: "Intelligently extracts endpoints, HTTP methods, headers, authentication tokens, and complete JSON body structures from any cURL command.",
      capabilities: [
        "Multi-format header parsing",
        "Complex authentication extraction", 
        "Nested JSON structure analysis",
        "URL parameter identification"
      ]
    },
    {
      icon: Brain,
      title: "Intelligent JSON Schema Inference", 
      description: "Automatically understands your API's data structure and generates meaningful test variations based on the provided request body.",
      capabilities: [
        "Dynamic type detection",
        "Nested object mapping",
        "Array structure analysis", 
        "Required field identification"
      ]
    },
    {
      icon: Shield,
      title: "Context-Aware Test Generation",
      description: "Goes beyond simple fuzzing by generating contextually relevant security tests based on your specific API endpoint and data.",
      capabilities: [
        "Business logic-aware testing",
        "Endpoint-specific vulnerabilities",
        "Role-based access testing",
        "Data-driven attack vectors"
      ]
    },
    {
      icon: Zap,
      title: "Automated Session Management",
      description: "Seamlessly uses the authentication token from your cURL command to maintain session state throughout the entire testing process.",
      capabilities: [
        "Bearer token handling",
        "Cookie session management",
        "API key authentication",
        "Custom header preservation"
      ]
    },
    {
      icon: BarChart3,
      title: "Stateful Response Analysis",
      description: "Compares test responses against the baseline to detect anomalies, unauthorized access, and security vulnerabilities.",
      capabilities: [
        "Response differential analysis",
        "Status code pattern detection",
        "Data exposure identification",
        "Timing attack detection"
      ]
    },
    {
      icon: FileSearch,
      title: "Actionable Reporting",
      description: "Provides clear, detailed reports showing exactly what was tested, what was found, and how to remediate any issues.",
      capabilities: [
        "Executive summary reports",
        "Technical remediation guides",
        "Risk prioritization",
        "Compliance mapping"
      ]
    }
  ];

  return (
    <section className="py-24 bg-background">
      <div className="container px-4">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold mb-6">
            Core <span className="bg-text-gradient bg-clip-text text-transparent">Technologies</span>
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            The foundational technologies that enable GreenAPI's revolutionary One-Curl approach, 
            making comprehensive API security testing accessible to everyone.
          </p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <Card key={index} className="bg-gradient-card border-primary/20 hover:shadow-elegant transition-all duration-300 h-full">
              <CardHeader>
                <div className="w-12 h-12 bg-primary/20 rounded-lg flex items-center justify-center mb-4">
                  <feature.icon className="w-6 h-6 text-primary" />
                </div>
                <CardTitle className="text-xl">{feature.title}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground mb-6">{feature.description}</p>
                <div>
                  <h4 className="font-semibold mb-3 text-primary">Key Capabilities</h4>
                  <ul className="space-y-2">
                    {feature.capabilities.map((capability, i) => (
                      <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                        <span className="text-primary mt-1">•</span>
                        {capability}
                      </li>
                    ))}
                  </ul>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="mt-16 bg-gradient-card border border-primary/20 rounded-xl p-8">
          <div className="grid md:grid-cols-2 gap-8 items-center">
            <div>
              <h3 className="text-2xl font-bold mb-4">Technology Integration</h3>
              <p className="text-muted-foreground mb-4">
                These core technologies work seamlessly together, creating a powerful testing engine 
                that transforms a simple cURL command into a comprehensive security assessment.
              </p>
              <p className="text-muted-foreground">
                The result is an unprecedented level of automation that democratizes API security testing, 
                empowering developers at any skill level to identify and fix vulnerabilities.
              </p>
            </div>
            <div className="bg-muted/50 rounded-lg p-6">
              <h4 className="font-semibold mb-3 text-primary">Processing Pipeline</h4>
              <div className="space-y-2 text-sm text-muted-foreground">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-primary rounded-full" />
                  <span>Parse cURL → Extract components</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-primary rounded-full" />
                  <span>Infer schema → Understand structure</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-primary rounded-full" />
                  <span>Generate tests → Context-aware vectors</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-primary rounded-full" />
                  <span>Execute → Maintain session state</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-primary rounded-full" />
                  <span>Analyze → Compare responses</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-primary rounded-full" />
                  <span>Report → Actionable insights</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};