import React, { useEffect, useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Chip,
  Divider,
  Collapse,
  Alert,
  CircularProgress,
  Button,
} from '@mui/material';
import {
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  ExpandMore as ExpandMoreIcon,
  Domain as DomainIcon,
  Download as DownloadIcon,
} from '@mui/icons-material';
import { jsPDF } from 'jspdf';
import 'jspdf-autotable';

const severityColor = (severity) => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'error';
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'info';
    default:
      return 'default';
  }
};

const vulnerabilityRecommendations = {
  xss: [
    'Implement context-aware output encoding',
    'Use Content Security Policy (CSP) headers',
    'Validate and sanitize all user inputs',
    'Set HttpOnly and Secure flags on cookies',
  ],
  sql_injection: [
    'Use prepared statements with parameterized queries',
    'Implement strict input validation',
    'Use ORM frameworks for database access',
    'Regularly update database software',
  ],
  missing_security_headers: [
    'Add Content-Security-Policy header',
    'Implement Strict-Transport-Security',
    'Set X-Content-Type-Options to "nosniff"',
    'Configure X-Frame-Options to "DENY"',
  ],
};

export default function ResultsView({ scanId, onResults }) {
  const [status, setStatus] = useState('pending');
  const [data, setData] = useState(null);
  const [expandedVuln, setExpandedVuln] = useState(null);

  const generatePdfReport = () => {
    const doc = new jsPDF();

    // Report Header
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(41, 128, 185); // Blue color
    doc.text(`Security Scan Report - ${new Date().toLocaleDateString()}`, 15, 20);

    // Scan Overview Section
    doc.setFontSize(12);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(0, 0, 0); // Black color
    doc.text(`Scanned URL: ${data.base_url}`, 15, 30);
    doc.text(`Pages Scanned: ${data.pages_scanned}`, 15, 35);
    doc.text(`Forms Found: ${data.forms_found}`, 15, 40);

    // Add a horizontal line separator
    doc.setDrawColor(200, 200, 200); // Light gray color
    doc.line(15, 45, 195, 45);

    // Vulnerabilities Section
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(41, 128, 185); // Blue color
    doc.text('Identified Vulnerabilities', 15, 55);

    // Prepare vulnerabilities table data
    const vulnData = data.vulnerabilities.map((vuln) => [
      vuln.vulnerability_type,
      vuln.severity,
      vuln.url,
      [...vuln.recommendation.split('.'), ...(vulnerabilityRecommendations[vuln.vulnerability_type.toLowerCase()] || [])]
        .filter((r) => r.trim())
        .join('\n'),
    ]);

    // Generate vulnerabilities table
    doc.autoTable({
      startY: 60,
      head: [['Type', 'Severity', 'Location', 'Recommendations']],
      body: vulnData,
      theme: 'striped',
      styles: { fontSize: 10, cellPadding: 3 },
      headStyles: { fillColor: [41, 128, 185], textColor: [255, 255, 255] }, // Blue header with white text
      columnStyles: {
        0: { cellWidth: 30 }, // Type column width
        1: { cellWidth: 20 }, // Severity column width
        2: { cellWidth: 50 }, // Location column width
        3: { cellWidth: 90 }, // Recommendations column width
      },
    });

    // Subdomains Section
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(41, 128, 185); // Blue color
    doc.text('Discovered Subdomains', 15, doc.autoTable.previous.finalY + 10);

    // Prepare subdomains table data
    const subdomainData = data.subdomains.map((sub) => [
      sub.subdomain,
      sub.status,
      sub.ip_address || 'N/A',
      sub.server || 'Unknown',
    ]);

    // Generate subdomains table
    doc.autoTable({
      startY: doc.autoTable.previous.finalY + 15,
      head: [['Subdomain', 'Status', 'IP Address', 'Server']],
      body: subdomainData,
      theme: 'striped',
      styles: { fontSize: 10, cellPadding: 3 },
      headStyles: { fillColor: [39, 174, 96], textColor: [255, 255, 255] }, // Green header with white text
      columnStyles: {
        0: { cellWidth: 50 }, // Subdomain column width
        1: { cellWidth: 30 }, // Status column width
        2: { cellWidth: 40 }, // IP Address column width
        3: { cellWidth: 50 }, // Server column width
      },
    });

    // Footer
    doc.setFontSize(10);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(100, 100, 100); // Gray color
    doc.text(`Report generated by Security Scanner on ${new Date().toLocaleString()}`, 15, doc.autoTable.previous.finalY + 10);

    // Save the PDF
    doc.save(`security_report_${scanId}.pdf`);
  };

  useEffect(() => {
    const checkStatus = async () => {
      try {
        const response = await fetch(`http://localhost:8000/api/scan/${scanId}`);
        const result = await response.json();

        setStatus(result.status);
        if (result.status === 'completed') {
          setData(result.results);
          onResults(result.results);
        }
      } catch (error) {
        console.error('Error:', error);
      }
    };

    const interval = setInterval(checkStatus, 2000);
    return () => clearInterval(interval);
  }, [scanId]);

  if (status === 'pending') {
    return (
      <Paper elevation={3} sx={{ p: 4, borderRadius: 4, textAlign: 'center' }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
          <CircularProgress size={60} thickness={4} />
          <Typography variant="h6" color="textSecondary">
            Scanning in progress...
          </Typography>
          <Typography variant="body2" color="textSecondary">
            This may take a few minutes
          </Typography>
        </Box>
      </Paper>
    );
  }

  if (status === 'failed') {
    return (
      <Paper elevation={3} sx={{ p: 4, borderRadius: 4 }}>
        <Alert severity="error" icon={<ErrorIcon fontSize="large" />}>
          <Typography variant="h6">Scan Failed</Typography>
          <Typography variant="body2">Please try again or check your network connection</Typography>
        </Alert>
      </Paper>
    );
  }

  if (!data) return null;

  return (
    <Paper elevation={3} sx={{ p: 4, borderRadius: 4 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 600 }}>
          Scan Results Overview
        </Typography>
        <Button
          variant="contained"
          startIcon={<DownloadIcon />}
          onClick={generatePdfReport}
          sx={{ borderRadius: 2 }}
        >
          Download Full Report
        </Button>
      </Box>

      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6}>
          <Paper sx={{ p: 3, borderRadius: 3 }}>
            <Typography variant="subtitle2" color="textSecondary">Pages Scanned</Typography>
            <Typography variant="h3" sx={{ fontWeight: 700 }}>{data.pages_scanned}</Typography>
          </Paper>
        </Grid>
        <Grid item xs={12} sm={6}>
          <Paper sx={{ p: 3, borderRadius: 3 }}>
            <Typography variant="subtitle2" color="textSecondary">Forms Found</Typography>
            <Typography variant="h3" sx={{ fontWeight: 700 }}>{data.forms_found}</Typography>
          </Paper>
        </Grid>
      </Grid>

      <Box sx={{ mb: 4 }}>
        <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
          Security Findings ({data.vulnerabilities.length})
        </Typography>

        {data.vulnerabilities.length === 0 ? (
          <Alert severity="success" icon={<CheckCircleIcon />}>
            No vulnerabilities detected - Great job!
          </Alert>
        ) : (
          <List sx={{ bgcolor: 'background.paper' }}>
            {data.vulnerabilities.map((vuln, index) => (
              <React.Fragment key={index}>
                <ListItem
                  button
                  onClick={() => setExpandedVuln(expandedVuln === index ? null : index)}
                  sx={{
                    borderRadius: 2,
                    '&:hover': { bgcolor: 'action.hover' },
                  }}
                >
                  <ListItemIcon>
                    <WarningIcon color={severityColor(vuln.severity)} />
                  </ListItemIcon>
                  <ListItemText
                    primary={vuln.vulnerability_type}
                    secondary={`Found in: ${vuln.url}`}
                  />
                  <Chip
                    label={vuln.severity}
                    color={severityColor(vuln.severity)}
                    sx={{ mr: 2 }}
                  />
                  <ExpandMoreIcon
                    sx={{
                      transform: expandedVuln === index ? 'rotate(180deg)' : 'none',
                      transition: 'transform 0.2s',
                    }}
                  />
                </ListItem>
                <Collapse in={expandedVuln === index}>
                  <Box sx={{ pl: 6, pr: 2, py: 2 }}>
                    <Divider sx={{ mb: 2 }} />
                    <Typography variant="body2" paragraph>
                      <strong>Description:</strong> {vuln.description}
                    </Typography>
                    <Typography variant="body2" paragraph>
                      <strong>Recommendations:</strong>
                    </Typography>
                    <List dense sx={{ listStyleType: 'disc', pl: 4 }}>
                      {[...vuln.recommendation.split('. '), ...(vulnerabilityRecommendations[vuln.vulnerability_type.toLowerCase()] || [])]
                        .filter((r) => r.trim())
                        .map((rec, i) => (
                          <ListItem key={i} sx={{ display: 'list-item' }}>
                            <Typography variant="body2">{rec}</Typography>
                          </ListItem>
                        ))}
                    </List>
                    {vuln.proof_of_concept && (
                      <Typography variant="caption" color="textSecondary">
                        <strong>Proof of Concept:</strong> {vuln.proof_of_concept}
                      </Typography>
                    )}
                  </Box>
                </Collapse>
                <Divider />
              </React.Fragment>
            ))}
          </List>
        )}
      </Box>

      <Box>
        <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
          Subdomain Discovery ({data.subdomains.length})
        </Typography>
        <List>
          {data.subdomains.map((subdomain, index) => (
            <ListItem
              key={index}
              sx={{
                borderRadius: 2,
                '&:hover': { bgcolor: 'action.hover' },
              }}
            >
              <ListItemIcon>
                <DomainIcon color={subdomain.status === 'Live' ? 'success' : 'disabled'} />
              </ListItemIcon>
              <ListItemText
                primary={subdomain.subdomain}
                secondary={`IP: ${subdomain.ip_address || 'N/A'} • Server: ${subdomain.server || 'Unknown'}`}
              />
              <Chip
                label={subdomain.status}
                color={subdomain.status === 'Live' ? 'success' : 'default'}
                variant="outlined"
              />
            </ListItem>
          ))}
        </List>
      </Box>
    </Paper>
  );
}