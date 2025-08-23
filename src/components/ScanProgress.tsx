import { useState, useEffect } from "react";
import { Shield, Zap, Lock, Search, AlertTriangle, CheckCircle, Loader2, Radar } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";

interface ScanProgressProps {
  isScanning: boolean;
  progress: number;
  currentTest: string;
  scanType: 'basic' | 'advanced' | 'custom';
}

export const ScanProgress = ({ 
  isScanning, 
  progress, 
  currentTest, 
  scanType
}: ScanProgressProps) => {
  const [pulseIntensity, setPulseIntensity] = useState(0);
  const [scanStage, setScanStage] = useState('initializing');

  const getScanTypeDescription = () => {
    switch (scanType) {
      case 'basic':
        return 'Running essential security checks';
      case 'advanced':
        return 'Performing comprehensive vulnerability assessment';
      case 'custom':
        return 'Testing with custom security payloads';
      default:
        return 'Scanning for security vulnerabilities';
    }
  };

  useEffect(() => {
    if (!isScanning) return;

    const interval = setInterval(() => {
      setPulseIntensity(prev => (prev + 1) % 4);
    }, 800);

    // Update scan stage based on progress
    if (progress < 20) setScanStage('initializing');
    else if (progress < 50) setScanStage('scanning');
    else if (progress < 80) setScanStage('analyzing');
    else setScanStage('finalizing');

    return () => clearInterval(interval);
  }, [isScanning, progress]);

  if (!isScanning) return null;

  const getScanIcon = () => {
    switch (scanStage) {
      case 'initializing': return <Search className="w-8 h-8" />;
      case 'scanning': return <Radar className="w-8 h-8" />;
      case 'analyzing': return <Shield className="w-8 h-8" />;
      case 'finalizing': return <CheckCircle className="w-8 h-8" />;
      default: return <Loader2 className="w-8 h-8" />;
    }
  };

  const getStageDescription = () => {
    switch (scanStage) {
      case 'initializing': return 'Preparing security tests...';
      case 'scanning': return 'Executing vulnerability tests...';
      case 'analyzing': return 'Analyzing API responses...';
      case 'finalizing': return 'Compiling security report...';
      default: return 'Processing...';
    }
  };


  return (
    <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center">
      <Card className="w-full max-w-lg mx-4 shadow-2xl border-primary/20">
        <CardContent className="p-8">
          {/* Main Scanning Animation */}
          <div className="flex flex-col items-center space-y-6">
            
            {/* Animated Scanner Icon */}
            <div className="relative">
              <div className={`absolute inset-0 rounded-full bg-primary/20 animate-ping ${
                pulseIntensity === 0 ? 'scale-100' : 
                pulseIntensity === 1 ? 'scale-110' : 
                pulseIntensity === 2 ? 'scale-125' : 'scale-140'
              }`} />
               <div className={`relative z-10 p-6 rounded-full bg-gradient-to-br from-primary/20 to-primary/10 border-2 border-primary/30 ${
                isScanning ? 'animate-spin' : ''
              }`}>
                <div className="text-primary">
                  {getScanIcon()}
                </div>
              </div>
            </div>

            {/* Title and Description */}
            <div className="text-center space-y-2">
              <h3 className="text-2xl font-bold bg-gradient-to-r from-primary to-primary/70 bg-clip-text text-transparent">
                Security Analysis in Progress
              </h3>
              <p className="text-muted-foreground">
                {getScanTypeDescription()}
              </p>
              <Badge variant={scanType === 'advanced' ? 'default' : 'secondary'} className="text-xs">
                {scanType.charAt(0).toUpperCase() + scanType.slice(1)} Scan
              </Badge>
            </div>

            {/* Progress Bar */}
            <div className="w-full space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground truncate max-w-[60%]">
                  {currentTest || 'Preparing tests...'}
                </span>
                <span className="text-primary font-bold">
                  {Math.round(progress)}%
                </span>
              </div>
              
              <div className="relative">
                <Progress 
                  value={progress} 
                  className="h-3 bg-secondary/50" 
                />
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent h-3 rounded-full animate-pulse" />
              </div>
            </div>

            {/* Security Test Icons Grid */}
            <div className="grid grid-cols-4 gap-4 mt-6">
              {[
                { icon: Shield, label: 'Auth' },
                { icon: Lock, label: 'BOLA' },
                { icon: Zap, label: 'Input' },
                { icon: AlertTriangle, label: 'Headers' },
              ].map(({ icon: Icon, label }, index) => (
                <div key={label} className="flex flex-col items-center space-y-2">
                  <div className={`p-3 rounded-lg border transition-all duration-300 bg-primary/10 border-primary/30 shadow-lg ${
                    progress > (index * 25) ? 'animate-pulse' : ''
                  }`}>
                    <Icon className="w-5 h-5 text-primary" />
                  </div>
                  <span className="text-xs font-medium text-foreground">
                    {label}
                  </span>
                </div>
              ))}
            </div>

            {/* Scanning Stats */}
            <div className="flex justify-between w-full text-center text-xs text-muted-foreground border-t pt-4">
              <div>
                <div className="font-medium text-foreground">
                  {scanType === 'custom' ? 'Custom' : scanType === 'advanced' ? '12+' : '5+'}
                </div>
                <div>Test Categories</div>
              </div>
              <div>
                <div className="font-medium text-foreground">
                  {scanType === 'advanced' ? '200+' : scanType === 'custom' ? 'Variable' : '50+'}
                </div>
                <div>Total Tests</div>
              </div>
              <div>
                <div className="font-medium text-foreground">OWASP</div>
                <div>API Top 10</div>
              </div>
            </div>

            {/* Animated dots */}
            <div className="flex space-x-1">
              {[0, 1, 2].map((i) => (
                <div
                  key={i}
                  className={`w-2 h-2 rounded-full bg-primary/50 animate-bounce`}
                  style={{ animationDelay: `${i * 0.2}s` }}
                />
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};