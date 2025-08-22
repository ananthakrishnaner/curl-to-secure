import jsPDF from 'jspdf';
import { Document, Packer, Paragraph, TextRun } from 'docx';
import JSZip from 'jszip';

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

export const exportToPDF = async (testResults: TestResult[], originalRequest: any, originalResponse: any) => {
  const pdf = new jsPDF();
  
  // Add title
  pdf.setFontSize(20);
  pdf.text('API Security Test Results', 20, 30);
  
  // Add metadata
  pdf.setFontSize(12);
  pdf.text(`Generated: ${new Date().toLocaleDateString()}`, 20, 45);
  pdf.text(`Total Tests: ${testResults.length}`, 20, 55);
  
  const failedTests = testResults.filter(r => r.status === 'failed').length;
  const warningTests = testResults.filter(r => r.status === 'warning').length;
  const passedTests = testResults.filter(r => r.status === 'passed').length;
  
  pdf.text(`Failed: ${failedTests} | Warnings: ${warningTests} | Passed: ${passedTests}`, 20, 65);
  
  // Add test results
  let yPosition = 85;
  testResults.forEach((result, index) => {
    if (yPosition > 250) {
      pdf.addPage();
      yPosition = 30;
    }
    
    pdf.setFontSize(14);
    pdf.text(`${index + 1}. ${result.name}`, 20, yPosition);
    yPosition += 10;
    
    pdf.setFontSize(10);
    pdf.text(`Status: ${result.status}`, 20, yPosition);
    pdf.text(`Severity: ${result.severity}`, 120, yPosition);
    yPosition += 10;
    
    pdf.text(`Description: ${result.description}`, 20, yPosition);
    yPosition += 10;
    
    pdf.text(`Response: ${result.response.status} ${result.response.statusText}`, 20, yPosition);
    yPosition += 15;
  });
  
  pdf.save('security-test-results.pdf');
};

export const exportToDocx = async (testResults: TestResult[], originalRequest: any, originalResponse: any) => {
  const doc = new Document({
    sections: [{
      properties: {},
      children: [
        new Paragraph({
          children: [
            new TextRun({
              text: "API Security Test Results",
              bold: true,
              size: 32,
            }),
          ],
        }),
        new Paragraph({
          children: [
            new TextRun({
              text: `Generated: ${new Date().toLocaleDateString()}`,
              size: 20,
            }),
          ],
        }),
        new Paragraph({
          children: [
            new TextRun({
              text: `Total Tests: ${testResults.length}`,
              size: 20,
            }),
          ],
        }),
        new Paragraph({
          children: [new TextRun({ text: "" })],
        }),
        ...testResults.flatMap((result, index) => [
          new Paragraph({
            children: [
              new TextRun({
                text: `${index + 1}. ${result.name}`,
                bold: true,
                size: 24,
              }),
            ],
          }),
          new Paragraph({
            children: [
              new TextRun({
                text: `Status: ${result.status} | Severity: ${result.severity}`,
                size: 20,
              }),
            ],
          }),
          new Paragraph({
            children: [
              new TextRun({
                text: `Description: ${result.description}`,
                size: 20,
              }),
            ],
          }),
          new Paragraph({
            children: [
              new TextRun({
                text: `Details: ${result.details.join(', ')}`,
                size: 20,
              }),
            ],
          }),
          new Paragraph({
            children: [
              new TextRun({
                text: `Response: ${result.response.status} ${result.response.statusText} (${result.response.time}ms)`,
                size: 20,
              }),
            ],
          }),
          new Paragraph({
            children: [new TextRun({ text: "" })],
          }),
        ]),
      ],
    }],
  });

  const buffer = await Packer.toBuffer(doc);
  const blob = new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'security-test-results.docx';
  a.click();
  URL.revokeObjectURL(url);
};

export const exportToZip = async (testResults: TestResult[], originalRequest: any, originalResponse: any) => {
  const zip = new JSZip();
  
  // Add JSON report
  const jsonReport = {
    timestamp: new Date().toISOString(),
    originalRequest: originalRequest,
    originalResponse: originalResponse,
    testResults: testResults,
    summary: {
      total: testResults.length,
      failed: testResults.filter(r => r.status === 'failed').length,
      warnings: testResults.filter(r => r.status === 'warning').length,
      passed: testResults.filter(r => r.status === 'passed').length
    }
  };
  zip.file('security-report.json', JSON.stringify(jsonReport, null, 2));
  
  // Add text summary
  let textSummary = 'API Security Test Results\n';
  textSummary += '========================\n\n';
  textSummary += `Generated: ${new Date().toLocaleDateString()}\n`;
  textSummary += `Total Tests: ${testResults.length}\n\n`;
  
  testResults.forEach((result, index) => {
    textSummary += `${index + 1}. ${result.name}\n`;
    textSummary += `   Status: ${result.status}\n`;
    textSummary += `   Severity: ${result.severity}\n`;
    textSummary += `   Description: ${result.description}\n`;
    textSummary += `   Details: ${result.details.join(', ')}\n`;
    textSummary += `   Response: ${result.response.status} ${result.response.statusText} (${result.response.time}ms)\n\n`;
  });
  zip.file('summary.txt', textSummary);
  
  // Add individual test result files
  testResults.forEach((result) => {
    const testData = {
      name: result.name,
      status: result.status,
      severity: result.severity,
      description: result.description,
      details: result.details,
      request: result.request,
      response: result.response
    };
    zip.file(`tests/${result.id}.json`, JSON.stringify(testData, null, 2));
  });
  
  const content = await zip.generateAsync({ type: 'blob' });
  const url = URL.createObjectURL(content);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'security-test-results.zip';
  a.click();
  URL.revokeObjectURL(url);
};