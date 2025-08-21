import { Shield, Users, Zap, CheckCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export const Conclusion = () => {
  const benefits = [
    {
      icon: Zap,
      title: "Instant Setup",
      description: "Zero configuration - works with any API immediately"
    },
    {
      icon: Users,
      title: "Universal Access", 
      description: "No security expertise required - accessible to all developers"
    },
    {
      icon: Shield,
      title: "Comprehensive Coverage",
      description: "Complete OWASP API Top 10 testing from a single command"
    },
    {
      icon: CheckCircle,
      title: "Actionable Results",
      description: "Clear reports with remediation guidance"
    }
  ];

  return (
    <section className="py-24 bg-gradient-hero">
      <div className="container px-4">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold mb-6">
            Democratizing <span className="bg-text-gradient bg-clip-text text-transparent">API Security</span>
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            GreenAPI represents a paradigm shift in API security testing. By reducing the complexity 
            to a single cURL command, we're making enterprise-grade security accessible to everyone.
          </p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
          {benefits.map((benefit, index) => (
            <Card key={index} className="bg-card/50 backdrop-blur-sm border-primary/20 text-center hover:shadow-elegant transition-all duration-300">
              <CardContent className="pt-6">
                <div className="w-12 h-12 bg-primary/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                  <benefit.icon className="w-6 h-6 text-primary" />
                </div>
                <h3 className="font-semibold mb-2">{benefit.title}</h3>
                <p className="text-sm text-muted-foreground">{benefit.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="bg-gradient-card border border-primary/20 rounded-xl p-8 mb-12">
          <div className="grid md:grid-cols-2 gap-8">
            <div>
              <h3 className="text-2xl font-bold mb-4">The Future of API Security</h3>
              <p className="text-muted-foreground mb-4">
                Traditional API security testing creates barriers: complex setup, specialized knowledge, 
                expensive tools, and time-consuming processes. These barriers leave many APIs vulnerable 
                because security testing becomes an afterthought.
              </p>
              <p className="text-muted-foreground">
                GreenAPI eliminates these barriers entirely. When security testing is as simple as 
                providing a cURL command, it becomes integrated into every developer's workflow, 
                creating a more secure digital ecosystem for everyone.
              </p>
            </div>
            <div className="bg-muted/50 rounded-lg p-6">
              <h4 className="font-semibold mb-4 text-primary">Impact Metrics</h4>
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-muted-foreground">Setup Time</span>
                  <span className="font-semibold text-primary">Hours → Seconds</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-muted-foreground">Security Expertise</span>
                  <span className="font-semibold text-primary">Expert → Anyone</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-muted-foreground">Test Coverage</span>
                  <span className="font-semibold text-primary">Partial → Complete</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-muted-foreground">Time to Results</span>
                  <span className="font-semibold text-primary">Days → Minutes</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="text-center">
          <h3 className="text-2xl font-bold mb-4">Ready to Revolutionize Your API Security?</h3>
          <p className="text-muted-foreground mb-8 max-w-2xl mx-auto">
            Join the security revolution. Experience the power of comprehensive API security testing 
            with just a single cURL command.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button size="lg" className="bg-gradient-primary hover:scale-105 transition-all duration-300 shadow-elegant">
              Start Testing Today
            </Button>
            <Button variant="outline" size="lg" className="border-primary/20 hover:bg-primary/10">
              Request Demo
            </Button>
          </div>
        </div>
      </div>
    </section>
  );
};