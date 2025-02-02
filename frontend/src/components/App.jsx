import React from 'react';
import ScanForm from './ScanForm'
import ResultsView from './ResultsView'
import { useState } from 'react';
import { CssBaseline, Container, Box, Typography, createTheme, ThemeProvider } from '@mui/material';
import { blue, deepOrange } from '@mui/material/colors';

// Create a custom theme
const theme = createTheme({
  palette: {
    primary: blue,
    secondary: deepOrange,
    background: {
      default: '#f5f7fa', // Light gray background
    },
  },
  typography: {
    fontFamily: 'Poppins, Arial, sans-serif',
  },
});

export default function App() {
  const [scanId, setScanId] = useState(null);
  const [results, setResults] = useState(null);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Container maxWidth="lg">
        <Box sx={{ 
          minHeight: '100vh', 
          py: 8,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center'
        }}>
          {/* Title */}
          <Typography 
            variant="h3" 
            component="h1" 
            gutterBottom 
            sx={{ 
              fontWeight: 600,
              color: 'primary.main',
              textAlign: 'center',
              mb: 6,
              textShadow: '0 2px 4px rgba(0,0,0,0.1)'
            }}
          >
            Web Vulnerability Scanner
          </Typography>

          {/* Scan Form */}
          <Box sx={{ 
            width: '100%', 
            maxWidth: 800, 
            mb: 4 
          }}>
            <ScanForm onScanStarted={setScanId} />
          </Box>

          {/* Results View */}
          {scanId && (
            <Box sx={{ 
              width: '100%', 
              mt: 4 
            }}>
              <ResultsView scanId={scanId} onResults={setResults} />
            </Box>
          )}
        </Box>
      </Container>
    </ThemeProvider>
  );
}