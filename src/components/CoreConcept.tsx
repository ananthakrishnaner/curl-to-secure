import { ArrowRight, Code, Shield, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export const CoreConcept = () => {
  const steps = [
    {
      icon: Code,
      title: "Provide a Single cURL",
      description: "Simply paste any valid cURL command from your API documentation or browser dev tools",
      example: "curl -X POST https://api.example.com/users"
    },
    {
      icon: Zap,
      title: "Intelligent Parsing & Analysis",
      description: "GreenAPI extracts endpoints, methods, headers, authentication tokens, and JSON schemas automatically",
      example: "Endpoint: /users | Method: POST | Auth: Bearer token"
    },
    {
      icon: Shield,
      title: "Comprehensive Security Testing",
      description: "Generate hundreds of security test cases covering all OWASP API Top 10 vulnerabilities",
      example: "BOLA, BOPLA, Authentication, Rate Limiting..."
    }
  ];

  return (
    <section className="py-24 bg-background">
      <div className="container px-4">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold mb-6">
            The <span className="bg-text-gradient bg-clip-text text-transparent">One-Curl</span> Revolution
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Traditional API security testing requires complex setup, multiple tools, and deep security expertise. 
            GreenAPI changes everything with our revolutionary one-command approach.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-8 mb-16">
          {steps.map((step, index) => (
            <div key={index} className="relative">
              <Card className="bg-gradient-card border-primary/20 h-full hover:shadow-elegant transition-all duration-300">
                <CardHeader>
                  <div className="w-12 h-12 bg-primary/20 rounded-lg flex items-center justify-center mb-4">
                    <step.icon className="w-6 h-6 text-primary" />
                  </div>
                  <CardTitle className="text-xl">{step.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-muted-foreground mb-4">{step.description}</p>
                  <div className="bg-muted/50 rounded-lg p-3 font-mono text-sm text-primary">
                    {step.example}
                  </div>
                </CardContent>
              </Card>
              
              {index < steps.length - 1 && (
                <div className="hidden md:block absolute top-1/2 -right-4 transform -translate-y-1/2 z-10">
                  <ArrowRight className="w-8 h-8 text-primary" />
                </div>
              )}
            </div>
          ))}
        </div>

        <div className="bg-gradient-card border border-primary/20 rounded-xl p-8">
          <h3 className="text-2xl font-bold mb-4 text-center">Why the One-Curl Approach Works</h3>
          <div className="grid md:grid-cols-2 gap-8">
            <div>
              <h4 className="text-lg font-semibold mb-3 text-primary">Technical Intelligence</h4>
              <ul className="space-y-2 text-muted-foreground">
                <li>• Advanced cURL parser extracts all request components</li>
                <li>• JSON schema inference understands data structures</li>
                <li>• Context-aware test generation based on real endpoints</li>
                <li>• Automated session management using extracted tokens</li>
              </ul>
            </div>
            <div>
              <h4 className="text-lg font-semibold mb-3 text-primary">Practical Benefits</h4>
              <ul className="space-y-2 text-muted-foreground">
                <li>• Zero configuration required</li>
                <li>• Works with any API immediately</li>
                <li>• No security expertise needed</li>
                <li>• Democratizes API security testing</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};