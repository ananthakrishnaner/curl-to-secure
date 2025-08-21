import { Hero } from "@/components/Hero";
import { CoreConcept } from "@/components/CoreConcept";
import { Features } from "@/components/Features";
import { OwaspSection } from "@/components/OwaspSection";
import { Conclusion } from "@/components/Conclusion";

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      <Hero />
      <CoreConcept />
      <Features />
      <OwaspSection />
      <Conclusion />
    </div>
  );
};

export default Index;
