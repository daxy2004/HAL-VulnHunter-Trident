import React, { useState } from 'react';
import {
  TextField,
  Button,
  Paper,
  Typography,
  Grid,
  LinearProgress,
  Alert,
  Box
} from '@mui/material';
import SendIcon from '@mui/icons-material/Send';

export default function ScanForm({ onScanStarted }) {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const response = await fetch('http://localhost:8000/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url,
          max_pages: 10,
          threads: 5
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to start scan');
      }

      const data = await response.json();
      onScanStarted(data.scan_id);
    } catch (error) {
      setError(error.message || 'An error occurred while starting the scan');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Paper elevation={3} sx={{ p: 4, borderRadius: 4, mb: 4 }}>
      <Typography variant="h5" component="h2" gutterBottom sx={{ fontWeight: 600 }}>
        Start New Security Scan
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      <form onSubmit={handleSubmit}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <TextField
              fullWidth
              label="Target URL"
              variant="outlined"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              required
              disabled={isLoading}
              InputProps={{
                sx: { borderRadius: 3 }
              }}
            />
          </Grid>

          <Grid item xs={12}>
            <Button
              fullWidth
              type="submit"
              variant="contained"
              size="large"
              disabled={isLoading}
              endIcon={!isLoading && <SendIcon />}
              sx={{
                py: 1.5,
                borderRadius: 3,
                textTransform: 'none',
                fontSize: 16,
                '&:hover': {
                  transform: 'translateY(-1px)',
                  boxShadow: 3
                }
              }}
            >
              {isLoading ? 'Initializing Scan...' : 'Start Security Scan'}
            </Button>
          </Grid>

          {isLoading && (
            <Grid item xs={12}>
              <LinearProgress 
                sx={{ 
                  height: 8,
                  borderRadius: 4,
                  '& .MuiLinearProgress-bar': {
                    borderRadius: 4
                  }
                }}
              />
            </Grid>
          )}
        </Grid>
      </form>

      <Box sx={{ mt: 2, textAlign: 'center' }}>
        <Typography variant="caption" color="textSecondary">
          By starting a scan, you agree to our responsible disclosure policy
        </Typography>
      </Box>
    </Paper>
  );
}