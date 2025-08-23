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
  const pdf = new jsPDF('p', 'mm', 'a4');
  
  // Define colors (matching application theme)
  const primaryColor = [72, 183, 115]; // HSL(142 71% 45%) converted to RGB
  const darkBg = [35, 39, 47]; // HSL(220 27% 8%) converted to RGB
  const cardBg = [48, 52, 63]; // HSL(220 24% 12%) converted to RGB
  const textColor = [249, 250, 251]; // HSL(210 40% 98%) converted to RGB
  const mutedColor = [156, 163, 175]; // HSL(215.4 16.3% 56.9%) converted to RGB
  
  // Header with gradient effect
  pdf.setFillColor(primaryColor[0], primaryColor[1], primaryColor[2]);
  pdf.rect(0, 0, 210, 35, 'F');
  
  // Title
  pdf.setTextColor(255, 255, 255);
  pdf.setFontSize(24);
  pdf.setFont('helvetica', 'bold');
  pdf.text('API Security Test Results', 20, 20);
  
  // Subtitle
  pdf.setFontSize(12);
  pdf.setFont('helvetica', 'normal');
  pdf.text('Comprehensive Security Analysis Report', 20, 28);
  
  // Reset text color for content
  pdf.setTextColor(0, 0, 0);
  
  // Report metadata section
  let yPos = 50;
  pdf.setFillColor(245, 245, 245);
  pdf.rect(15, yPos - 5, 180, 25, 'F');
  
  pdf.setFontSize(14);
  pdf.setFont('helvetica', 'bold');
  pdf.text('Report Summary', 20, yPos + 3);
  
  pdf.setFontSize(10);
  pdf.setFont('helvetica', 'normal');
  const reportDate = new Date().toLocaleDateString('en-US', { 
    year: 'numeric', 
    month: 'long', 
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
  pdf.text(`Generated: ${reportDate}`, 20, yPos + 10);
  pdf.text(`Total Tests Executed: ${testResults.length}`, 20, yPos + 16);
  
  const failedTests = testResults.filter(r => r.status === 'failed').length;
  const warningTests = testResults.filter(r => r.status === 'warning').length;
  const passedTests = testResults.filter(r => r.status === 'passed').length;
  
  // Status indicators with colors
  pdf.setTextColor(220, 38, 38); // Red for failed
  pdf.text(`Failed: ${failedTests}`, 130, yPos + 10);
  pdf.setTextColor(245, 158, 11); // Orange for warnings
  pdf.text(`Warnings: ${warningTests}`, 130, yPos + 16);
  pdf.setTextColor(34, 197, 94); // Green for passed
  pdf.text(`Passed: ${passedTests}`, 170, yPos + 16);
  
  pdf.setTextColor(0, 0, 0); // Reset to black
  yPos += 35;
  
  // Original Request Section
  if (originalRequest) {
    pdf.setFillColor(primaryColor[0], primaryColor[1], primaryColor[2]);
    pdf.rect(15, yPos, 180, 8, 'F');
    pdf.setTextColor(255, 255, 255);
    pdf.setFontSize(12);
    pdf.setFont('helvetica', 'bold');
    pdf.text('Original Request Details', 20, yPos + 5);
    pdf.setTextColor(0, 0, 0);
    yPos += 15;
    
    pdf.setFontSize(9);
    pdf.setFont('helvetica', 'normal');
    pdf.text(`Method: ${originalRequest.method || 'GET'}`, 20, yPos);
    yPos += 5;
    
    const urlText = `URL: ${originalRequest.url || 'N/A'}`;
    const urlLines = pdf.splitTextToSize(urlText, 170);
    pdf.text(urlLines, 20, yPos);
    yPos += urlLines.length * 5;
    
    if (originalRequest.headers && Object.keys(originalRequest.headers).length > 0) {
      pdf.setFont('helvetica', 'bold');
      pdf.text('Headers:', 20, yPos);
      pdf.setFont('helvetica', 'normal');
      yPos += 5;
      
      Object.entries(originalRequest.headers).forEach(([key, value]) => {
        const headerText = `  ${key}: ${value}`;
        const headerLines = pdf.splitTextToSize(headerText, 160);
        pdf.text(headerLines, 25, yPos);
        yPos += headerLines.length * 4;
      });
    }
    
    if (originalRequest.body) {
      pdf.setFont('helvetica', 'bold');
      pdf.text('Request Body:', 20, yPos);
      pdf.setFont('helvetica', 'normal');
      yPos += 5;
      
      const bodyText = typeof originalRequest.body === 'string' 
        ? originalRequest.body 
        : JSON.stringify(originalRequest.body, null, 2);
      const bodyLines = pdf.splitTextToSize(bodyText, 160);
      pdf.text(bodyLines, 25, yPos);
      yPos += bodyLines.length * 4;
    }
    yPos += 10;
  }
  
  // Test Results Section
  pdf.setFillColor(primaryColor[0], primaryColor[1], primaryColor[2]);
  pdf.rect(15, yPos, 180, 8, 'F');
  pdf.setTextColor(255, 255, 255);
  pdf.setFontSize(12);
  pdf.setFont('helvetica', 'bold');
  pdf.text('Security Test Results', 20, yPos + 5);
  pdf.setTextColor(0, 0, 0);
  yPos += 20;
  
  // Individual test results in table format
  testResults.forEach((result, index) => {
    // Check if we need a new page
    if (yPos > 220) {
      pdf.addPage();
      yPos = 20;
    }
    
    // Test header with status color
    pdf.setFillColor(250, 250, 250);
    pdf.rect(15, yPos - 3, 180, 12, 'F');
    
    // Status color indicator
    let statusColor = [34, 197, 94]; // Green
    if (result.status === 'failed') statusColor = [220, 38, 38]; // Red
    if (result.status === 'warning') statusColor = [245, 158, 11]; // Orange
    
    pdf.setFillColor(statusColor[0], statusColor[1], statusColor[2]);
    pdf.rect(15, yPos - 3, 5, 12, 'F');
    
    pdf.setTextColor(0, 0, 0);
    pdf.setFontSize(11);
    pdf.setFont('helvetica', 'bold');
    pdf.text(`Test ${index + 1}: ${result.name}`, 25, yPos + 2);
    
    // Status and severity in header
    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(9);
    pdf.text(`${result.status.toUpperCase()} | ${result.severity} | ${result.response.time}ms`, 25, yPos + 7);
    yPos += 15;
    
    // Description
    const descLines = pdf.splitTextToSize(result.description, 160);
    pdf.text(descLines, 25, yPos);
    yPos += descLines.length * 4 + 5;
    
    // Create test details table
    const tableStartY = yPos;
    const tableWidth = 170;
    const colWidth = tableWidth / 2;
    
    // Table headers
    pdf.setFillColor(240, 240, 240);
    pdf.rect(15, yPos, tableWidth, 8, 'F');
    pdf.setFont('helvetica', 'bold');
    pdf.setFontSize(10);
    pdf.text('REQUEST', 20, yPos + 5);
    pdf.text('RESPONSE', 20 + colWidth, yPos + 5);
    yPos += 10;
    
    // Calculate content heights for both columns
    const requestContent = [];
    const responseContent = [];
    
    // Request content
    requestContent.push(`Method: ${result.request.method}`);
    requestContent.push(`URL: ${result.request.url}`);
    
    if (result.request.headers && Object.keys(result.request.headers).length > 0) {
      requestContent.push('Headers:');
      Object.entries(result.request.headers).forEach(([key, value]) => {
        requestContent.push(`  ${key}: ${value}`);
      });
    }
    
    if (result.request.body) {
      const bodyText = typeof result.request.body === 'string' 
        ? result.request.body 
        : JSON.stringify(result.request.body, null, 2);
      requestContent.push('Body:');
      const bodyLines = bodyText.split('\n');
      requestContent.push(...bodyLines);
    }
    
    // Response content
    responseContent.push(`Status: ${result.response.status} ${result.response.statusText}`);
    
    if (result.response.headers && Object.keys(result.response.headers).length > 0) {
      responseContent.push('Headers:');
      Object.entries(result.response.headers).forEach(([key, value]) => {
        responseContent.push(`  ${key}: ${value}`);
      });
    }
    
    if (result.response.body) {
      const respBodyText = typeof result.response.body === 'string' 
        ? result.response.body 
        : JSON.stringify(result.response.body, null, 2);
      responseContent.push('Body:');
      const bodyLines = respBodyText.split('\n');
      responseContent.push(...bodyLines);
    }
    
    // Calculate table height
    const maxLines = Math.max(requestContent.length, responseContent.length);
    const tableHeight = maxLines * 4 + 5;
    
    // Draw table border
    pdf.setDrawColor(200, 200, 200);
    pdf.rect(15, tableStartY, tableWidth, tableHeight + 8);
    pdf.line(15 + colWidth, tableStartY, 15 + colWidth, tableStartY + tableHeight + 8);
    
    // Fill table content
    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(8);
    
    let currentY = yPos;
    
    // Request column
    requestContent.forEach((line, i) => {
      const lineY = currentY + (i * 4);
      const processedLine = pdf.splitTextToSize(line, colWidth - 10);
      pdf.text(processedLine, 20, lineY);
    });
    
    // Response column
    responseContent.forEach((line, i) => {
      const lineY = currentY + (i * 4);
      const processedLine = pdf.splitTextToSize(line, colWidth - 10);
      pdf.text(processedLine, 20 + colWidth + 5, lineY);
    });
    
    yPos += tableHeight + 10;
    
    // Details section below table
    if (result.details && result.details.length > 0) {
      pdf.setFont('helvetica', 'bold');
      pdf.setFontSize(9);
      pdf.text('Test Details:', 25, yPos);
      pdf.setFont('helvetica', 'normal');
      yPos += 4;
      
      result.details.forEach(detail => {
        const detailLines = pdf.splitTextToSize(`• ${detail}`, 160);
        pdf.text(detailLines, 25, yPos);
        yPos += detailLines.length * 4;
      });
    }
    
    yPos += 10; // Space between tests
  });
  
  // Footer on each page
  const pageCount = (pdf as any).internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    pdf.setPage(i);
    pdf.setFillColor(primaryColor[0], primaryColor[1], primaryColor[2]);
    pdf.rect(0, 287, 210, 10, 'F');
    pdf.setTextColor(255, 255, 255);
    pdf.setFontSize(8);
    pdf.text(`Page ${i} of ${pageCount}`, 20, 293);
    pdf.text('Generated by API Security Tester', 140, 293);
  }
  
  pdf.save('security-test-results.pdf');
};

export const exportToDocx = async (testResults: TestResult[], originalRequest: any, originalResponse: any) => {
  try {
    console.log('📄 Starting DOCX generation with:', { testResultsCount: testResults.length });
  const reportDate = new Date().toLocaleDateString('en-US', { 
    year: 'numeric', 
    month: 'long', 
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });

  const failedTests = testResults.filter(r => r.status === 'failed').length;
  const warningTests = testResults.filter(r => r.status === 'warning').length;
  const passedTests = testResults.filter(r => r.status === 'passed').length;

  const children = [
    // Title
    new Paragraph({
      children: [
        new TextRun({
          text: "API Security Test Results",
          bold: true,
          size: 32,
          color: "48B773",
        }),
      ],
    }),
    new Paragraph({
      children: [
        new TextRun({
          text: "Comprehensive Security Analysis Report",
          size: 20,
          color: "6B7280",
        }),
      ],
    }),
    new Paragraph({ children: [new TextRun({ text: "" })] }),

    // Report Summary
    new Paragraph({
      children: [
        new TextRun({
          text: "Report Summary",
          bold: true,
          size: 24,
        }),
      ],
    }),
    new Paragraph({
      children: [
        new TextRun({
          text: `Generated: ${reportDate}`,
          size: 20,
        }),
      ],
    }),
    new Paragraph({
      children: [
        new TextRun({
          text: `Total Tests Executed: ${testResults.length}`,
          size: 20,
        }),
      ],
    }),
    new Paragraph({
      children: [
        new TextRun({
          text: `Failed: ${failedTests} | Warnings: ${warningTests} | Passed: ${passedTests}`,
          size: 20,
        }),
      ],
    }),
    new Paragraph({ children: [new TextRun({ text: "" })] }),
  ];

  // Original Request Section
  if (originalRequest) {
    children.push(
      new Paragraph({
        children: [
          new TextRun({
            text: "Original Request Details",
            bold: true,
            size: 22,
            color: "48B773",
          }),
        ],
      }),
      new Paragraph({
        children: [
          new TextRun({
            text: `Method: ${originalRequest.method || 'GET'}`,
            size: 18,
          }),
        ],
      }),
      new Paragraph({
        children: [
          new TextRun({
            text: `URL: ${originalRequest.url || 'N/A'}`,
            size: 18,
          }),
        ],
      })
    );

    if (originalRequest.headers && Object.keys(originalRequest.headers).length > 0) {
      children.push(
        new Paragraph({
          children: [
            new TextRun({
              text: "Headers:",
              bold: true,
              size: 18,
            }),
          ],
        })
      );
      
      Object.entries(originalRequest.headers).forEach(([key, value]) => {
        children.push(
          new Paragraph({
            children: [
              new TextRun({
                text: `  ${key}: ${value}`,
                size: 16,
              }),
            ],
          })
        );
      });
    }

    if (originalRequest.body) {
      const bodyText = typeof originalRequest.body === 'string' 
        ? originalRequest.body 
        : JSON.stringify(originalRequest.body, null, 2);
      
      children.push(
        new Paragraph({
          children: [
            new TextRun({
              text: "Request Body:",
              bold: true,
              size: 18,
            }),
          ],
        }),
        new Paragraph({
          children: [
            new TextRun({
              text: bodyText,
              size: 16,
            }),
          ],
        })
      );
    }
    
    children.push(new Paragraph({ children: [new TextRun({ text: "" })] }));
  }

  // Security Test Results Section
  children.push(
    new Paragraph({
      children: [
        new TextRun({
          text: "Security Test Results",
          bold: true,
          size: 22,
          color: "48B773",
        }),
      ],
    }),
    new Paragraph({ children: [new TextRun({ text: "" })] })
  );

  // Individual test results in table format
  testResults.forEach((result, index) => {
    children.push(
      new Paragraph({
        children: [
          new TextRun({
            text: `Test ${index + 1}: ${result.name}`,
            bold: true,
            size: 20,
            color: "48B773",
          }),
        ],
      }),
      new Paragraph({
        children: [
          new TextRun({
            text: `Description: ${result.description}`,
            size: 14,
          }),
        ],
      }),
      new Paragraph({ children: [new TextRun({ text: "" })] })
    );

    // Table header
    children.push(
      new Paragraph({
        children: [
          new TextRun({
            text: "REQUEST DETAILS",
            bold: true,
            size: 14,
            color: "48B773",
          }),
          new TextRun({
            text: "\t\t\t\tRESPONSE DETAILS",
            bold: true,
            size: 14,
            color: "48B773",
          }),
        ],
      })
    );

    // Request and Response content side by side
    const requestDetails = [];
    const responseDetails = [];

    // Build request details
    requestDetails.push(`Method: ${result.request.method}`);
    requestDetails.push(`URL: ${result.request.url}`);
    
    if (result.request.headers && Object.keys(result.request.headers).length > 0) {
      requestDetails.push("Headers:");
      Object.entries(result.request.headers).forEach(([key, value]) => {
        requestDetails.push(`  ${key}: ${value}`);
      });
    }

    if (result.request.body) {
      const bodyText = typeof result.request.body === 'string' 
        ? result.request.body 
        : JSON.stringify(result.request.body, null, 2);
      requestDetails.push("Request Body:");
      requestDetails.push(bodyText);
    }

    // Build response details
    responseDetails.push(`Status: ${result.response.status} ${result.response.statusText}`);
    
    if (result.response.headers && Object.keys(result.response.headers).length > 0) {
      responseDetails.push("Headers:");
      Object.entries(result.response.headers).forEach(([key, value]) => {
        responseDetails.push(`  ${key}: ${value}`);
      });
    }

    if (result.response.body) {
      const respBodyText = typeof result.response.body === 'string' 
        ? result.response.body 
        : JSON.stringify(result.response.body, null, 2);
      responseDetails.push("Response Body:");
      responseDetails.push(respBodyText);
    }

    // Create table-like structure
    const maxLines = Math.max(requestDetails.length, responseDetails.length);
    for (let i = 0; i < maxLines; i++) {
      const requestLine = requestDetails[i] || "";
      const responseLine = responseDetails[i] || "";
      
      children.push(
        new Paragraph({
          children: [
            new TextRun({
              text: requestLine.padEnd(50),
              size: 12,
              font: "Courier New",
            }),
            new TextRun({
              text: `\t${responseLine}`,
              size: 12,
              font: "Courier New",
            }),
          ],
        })
      );
    }

    // Details section
    if (result.details && result.details.length > 0) {
      children.push(
        new Paragraph({ children: [new TextRun({ text: "" })] }),
        new Paragraph({
          children: [
            new TextRun({
              text: "Test Details:",
              bold: true,
              size: 14,
            }),
          ],
        })
      );
      
      result.details.forEach(detail => {
        children.push(
          new Paragraph({
            children: [
              new TextRun({
                text: `• ${detail}`,
                size: 12,
              }),
            ],
          })
        );
      });
    }

    children.push(
      new Paragraph({ children: [new TextRun({ text: "" })] }),
      new Paragraph({ children: [new TextRun({ text: "─".repeat(80) })] }),
      new Paragraph({ children: [new TextRun({ text: "" })] })
    );
  });

  console.log('📄 Creating DOCX document...');
  const doc = new Document({
    sections: [{
      properties: {},
      children: children,
    }],
  });

  console.log('📄 Converting to buffer...');
  const buffer = await Packer.toBuffer(doc);
  console.log('📄 Creating blob...');
  const blob = new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'security-test-results.docx';
  a.click();
  URL.revokeObjectURL(url);
  console.log('✅ DOCX export completed successfully');
  } catch (error) {
    console.error('❌ DOCX export error:', error);
    throw error;
  }
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

export const exportToMarkdown = async (testResults: TestResult[], originalRequest: any, originalResponse: any) => {
  const reportDate = new Date().toLocaleDateString('en-US', { 
    year: 'numeric', 
    month: 'long', 
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });

  const failedTests = testResults.filter(r => r.status === 'failed').length;
  const warningTests = testResults.filter(r => r.status === 'warning').length;
  const passedTests = testResults.filter(r => r.status === 'passed').length;

  let markdown = '';
  
  // Title
  markdown += '# API Security Test Results\n\n';
  markdown += '*Comprehensive Security Analysis Report*\n\n';
  
  // Report Summary
  markdown += '## 📊 Report Summary\n\n';
  markdown += `- **Generated:** ${reportDate}\n`;
  markdown += `- **Total Tests Executed:** ${testResults.length}\n`;
  markdown += `- **Failed:** ${failedTests} ❌\n`;
  markdown += `- **Warnings:** ${warningTests} ⚠️\n`;
  markdown += `- **Passed:** ${passedTests} ✅\n\n`;
  
  // Original Request Section
  if (originalRequest) {
    markdown += '## 🌐 Original Request Details\n\n';
    markdown += `**Method:** \`${originalRequest.method || 'GET'}\`\n\n`;
    markdown += `**URL:** \`${originalRequest.url || 'N/A'}\`\n\n`;
    
    if (originalRequest.headers && Object.keys(originalRequest.headers).length > 0) {
      markdown += '### Headers\n\n';
      markdown += '```\n';
      Object.entries(originalRequest.headers).forEach(([key, value]) => {
        markdown += `${key}: ${value}\n`;
      });
      markdown += '```\n\n';
    }
    
    if (originalRequest.body) {
      const bodyText = typeof originalRequest.body === 'string' 
        ? originalRequest.body 
        : JSON.stringify(originalRequest.body, null, 2);
      markdown += '### Request Body\n\n';
      markdown += '```json\n';
      markdown += bodyText;
      markdown += '\n```\n\n';
    }
  }
  
  // Test Results Section
  markdown += '## 🔒 Security Test Results\n\n';
  
  testResults.forEach((result, index) => {
    const statusEmoji = result.status === 'failed' ? '❌' : result.status === 'warning' ? '⚠️' : '✅';
    const severityEmoji = result.severity === 'Critical' ? '🔴' : result.severity === 'High' ? '🟠' : result.severity === 'Medium' ? '🟡' : '🟢';
    
    markdown += `### ${index + 1}. ${result.name} ${statusEmoji}\n\n`;
    markdown += `**Description:** ${result.description}\n\n`;
    
    // Request Details Section
    markdown += '#### 📤 Request Details\n\n';
    markdown += `**Method:** \`${result.request.method}\`\n\n`;
    markdown += `**URL:** \`${result.request.url}\`\n\n`;
    
    if (result.request.headers && Object.keys(result.request.headers).length > 0) {
      markdown += '**Headers:**\n```\n';
      Object.entries(result.request.headers).forEach(([key, value]) => {
        markdown += `${key}: ${value}\n`;
      });
      markdown += '```\n\n';
    }
    
    if (result.request.body) {
      const bodyText = typeof result.request.body === 'string' 
        ? result.request.body 
        : JSON.stringify(result.request.body, null, 2);
      markdown += '**Request Body:**\n```json\n';
      markdown += bodyText;
      markdown += '\n```\n\n';
    }
    
    // Response Details Section
    markdown += '#### 📥 Response Details\n\n';
    markdown += `**Status:** \`${result.response.status} ${result.response.statusText}\`\n\n`;
    
    if (result.response.headers && Object.keys(result.response.headers).length > 0) {
      markdown += '**Headers:**\n```\n';
      Object.entries(result.response.headers).forEach(([key, value]) => {
        markdown += `${key}: ${value}\n`;
      });
      markdown += '```\n\n';
    }
    
    if (result.response.body) {
      const respBodyText = typeof result.response.body === 'string' 
        ? result.response.body 
        : JSON.stringify(result.response.body, null, 2);
      markdown += '**Response Body:**\n```json\n';
      markdown += respBodyText;
      markdown += '\n```\n\n';
    }
    
    // Test Details
    if (result.details && result.details.length > 0) {
      markdown += '#### 🔍 Test Details\n\n';
      result.details.forEach(detail => {
        markdown += `- ${detail}\n`;
      });
      markdown += '\n';
    }
    
    markdown += '---\n\n';
  });
  
  // Footer
  markdown += '*Generated by API Security Tester*\n';
  
  // Download the markdown file
  const blob = new Blob([markdown], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'security-test-results.md';
  a.click();
  URL.revokeObjectURL(url);
};