import { Shield, Terminal, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";

export const Hero = () => {
  return (
    <section className="relative min-h-screen flex items-center justify-center bg-gradient-hero overflow-hidden">
      {/* Background effects */}
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-primary/10" />
      <div className="absolute top-1/4 left-1/4 w-64 h-64 bg-primary/20 rounded-full blur-3xl animate-pulse" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-primary/10 rounded-full blur-3xl animate-pulse delay-1000" />
      
      <div className="container relative z-10 text-center px-4">
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-card border border-primary/20 mb-8 animate-fade-in">
          <Shield className="w-4 h-4 text-primary" />
          <span className="text-sm text-muted-foreground">Revolutionary API Security Testing</span>
        </div>
        
        <h1 className="text-5xl md:text-7xl font-bold mb-6 animate-fade-in">
          <span className="bg-text-gradient bg-clip-text text-transparent">
            GreenAPI
          </span>
        </h1>
        
        <p className="text-xl md:text-2xl text-muted-foreground mb-8 max-w-3xl mx-auto animate-fade-in">
          One cURL command. Complete API security assessment. 
          <br />
          <span className="text-primary font-semibold">Provide a cURL, and we'll handle the rest.</span>
        </p>
        
        <div className="flex flex-col sm:flex-row gap-4 justify-center items-center mb-12 animate-fade-in">
          <Button size="lg" className="bg-gradient-primary hover:scale-105 transition-all duration-300 shadow-elegant">
            <Terminal className="w-5 h-5 mr-2" />
            Try the One-Curl Approach
          </Button>
          <Button variant="outline" size="lg" className="border-primary/20 hover:bg-primary/10">
            <Zap className="w-5 h-5 mr-2" />
            Explore Features
          </Button>
        </div>
        
        {/* Demo cURL command */}
        <div className="max-w-4xl mx-auto">
          <div className="bg-card/50 backdrop-blur-sm border border-primary/20 rounded-lg p-6 font-mono text-left text-sm animate-fade-in">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-3 h-3 bg-destructive rounded-full" />
              <div className="w-3 h-3 bg-security-yellow rounded-full" />
              <div className="w-3 h-3 bg-primary rounded-full" />
              <span className="text-muted-foreground ml-2">Terminal</span>
            </div>
            <div className="text-primary">
              <span>$ curl -X POST https://api.example.com/users \</span><br />
              <span>&nbsp;&nbsp;-H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \</span><br />
              <span>&nbsp;&nbsp;-H "Content-Type: application/json" \</span><br />
              <span>&nbsp;&nbsp;-d '{`{"userId": 123, "role": "user", "email": "test@example.com"}`}'</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};