import { useState, useEffect } from 'react';
import { 
  Box, 
  TextField, 
  Button, 
  Paper, 
  Typography, 
  CircularProgress,
  Alert,
  AlertTitle,
  Snackbar,
  Collapse,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Chip,
  Tooltip,
  IconButton,
  Fade
} from '@mui/material';
import {
  Send as SendIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  ContentCopy as CopyIcon,
  OpenInNew as OpenInNewIcon
} from '@mui/icons-material';
import styles from './UrlScanner.module.css';

function UrlScanner({ onNewScan }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const [expanded, setExpanded] = useState(false);
  
  // Copy URL to clipboard
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };
  
  // Open URL in new tab
  const openInNewTab = (url) => {
    window.open(url, '_blank', 'noopener,noreferrer');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          url,
          // Include additional metadata that might be useful
          userAgent: navigator.userAgent,
          ipAddress: '' // Will be set by the server
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to scan URL');
      }

      const data = await response.json();
      setResult(data);
      setOpenSnackbar(true);
      onNewScan?.(data);
    } catch (err) {
      setError(err.message || 'An error occurred while scanning the URL');
      setOpenSnackbar(true);
    } finally {
      setLoading(false);
    }
  };

  const handleCloseSnackbar = () => {
    setOpenSnackbar(false);
  };

  return (
    <Paper elevation={3} className={styles.container}>
      <div className={styles.header}>
        <SecurityIcon color="primary" />
        <Typography variant="h5" gutterBottom>
          URL Safety Check
        </Typography>
      </div>
      
      <form onSubmit={handleSubmit} className={styles.formContainer}>
        <div className={styles.formRow}>
          <TextField
            fullWidth
            variant="outlined"
            label="Enter URL to scan"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={loading}
            placeholder="https://example.com"
            size="small"
            className={styles.urlInput}
            InputProps={{
              startAdornment: result && (
                <Box sx={{ 
                  mr: 1, 
                  display: 'flex',
                  alignItems: 'center',
                  color: result.isPhishing === true || (result.confidence >= 80)
                    ? 'error.main' 
                    : result.is_suspicious === true || (result.confidence >= 55 && result.confidence < 80)
                      ? 'warning.main' 
                      : 'success.main'
                }}>
                  {result.isPhishing === true || (result.confidence >= 80) 
                    ? <WarningIcon /> 
                    : result.is_suspicious === true || (result.confidence >= 55 && result.confidence < 80)
                      ? <WarningIcon /> 
                      : <CheckCircleIcon />
                  }
                </Box>
              )
            }}
          />
          <Button
            type="submit"
            variant="contained"
            color="primary"
            disabled={!url || loading}
            className={styles.scanButton}
            endIcon={loading ? <CircularProgress size={20} /> : <SendIcon />}
          >
            {loading ? 'Scanning...' : 'Scan'}
          </Button>
        </div>
      </form>


      {/* Scan Results */}
      {result && (
        <Fade in={!!result}>
          <div className={styles.resultContainer}>
            <Alert 
              severity={
                result.isPhishing === true || (result.confidence >= 80)
                  ? 'error' 
                  : result.is_suspicious === true || (result.confidence >= 55 && result.confidence < 80)
                    ? 'warning' 
                    : 'success'
              } 
              className={styles.resultAlert}
              action={
                <IconButton 
                  aria-label="toggle details"
                  size="small" 
                  onClick={() => setExpanded(!expanded)}
                  className={styles.detailsButton}
                >
                  <InfoIcon />
                </IconButton>
              }
            >
              <AlertTitle className={styles.alertTitle}>
                {result.isPhishing 
                  ? '⚠️ Potential Phishing Detected' 
                  : result.is_suspicious 
                    ? '⚠️ Suspicious URL Detected' 
                    : '✅ This URL appears to be safe'}
              </AlertTitle>
              <div className={styles.alertContent}>
                <div className={styles.alertTopRow}>
                  <Chip 
                    label={`${result.confidence.toFixed(2)}% confidence`} 
                    size="small" 
                    color={
                      result.isPhishing
                        ? 'error' 
                        : result.is_suspicious
                          ? 'warning' 
                          : 'success'
                    }
                    variant="outlined"
                    className={styles.confidenceBadge}
                  />
                  {result.suspicious_factors?.length > 0 && (
                    <Chip 
                      label={`${result.suspicious_factors.length} suspicious ${result.suspicious_factors.length === 1 ? 'factor' : 'factors'}`}
                      size="small"
                      color="warning"
                      variant="outlined"
                      className={styles.factorsBadge}
                    />
                  )}
                </div>
                {(result.isPhishing || result.is_suspicious) && (
                  <div className={styles.reasonContainer}>
                    <div className={styles.reasonHeader}>
                      <Typography variant="body2" className={styles.reasonText}>
                        <strong>Main Reason:</strong> {
                          // First try main_reason, then reason, then check if there are any suspicious factors or reasons
                          result.main_reason || 
                          result.reason || 
                          (result.suspicious_factors?.length > 0 ? 'Suspicious characteristics detected' : 
                          (result.reasons?.length > 0 ? 'Multiple suspicious indicators detected' : 
                          'No specific reason provided'))
                        }
                      </Typography>
                      {!(result.main_reason || result.reason) && (result.suspicious_factors?.length > 0 || result.reasons?.length > 0) && (
                        <Typography variant="caption" color="textSecondary" className={styles.secondaryText}>
                          (Based on analysis of URL characteristics)
                        </Typography>
                      )}
                    </div>
                    
                    {(result.reasons?.length > 0 || result.suspicious_factors?.length > 0) && (
                      <div className={styles.detailedReasons}>
                        <Typography variant="caption" color="textSecondary" component="div" className={styles.detailedReasonsTitle}>
                          <strong>Detailed Indicators:</strong>
                        </Typography>
                        <List dense disablePadding>
                          {/* Show suspicious factors first */}
                          {result.suspicious_factors?.map((factor, idx) => (
                            <ListItem key={`factor-${idx}`} disableGutters className={styles.reasonItem}>
                              <ListItemIcon className={styles.reasonIcon}>
                                <WarningIcon color="warning" fontSize="small" />
                              </ListItemIcon>
                              <ListItemText 
                                primary={factor} 
                                primaryTypographyProps={{ variant: 'body2' }}
                              />
                            </ListItem>
                          ))}
                          {/* Then show detailed reasons */}
                          {result.reasons?.map((reason, idx) => (
                            <ListItem key={`reason-${idx}`} disableGutters className={styles.reasonItem}>
                              <ListItemIcon className={styles.reasonIcon}>
                                <WarningIcon color="warning" fontSize="small" />
                              </ListItemIcon>
                              <ListItemText 
                                primary={reason} 
                                primaryTypographyProps={{ variant: 'body2' }}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </Alert>

            <Collapse in={expanded} timeout="auto" unmountOnExit>
              <Paper elevation={1} className={styles.detailsSection}>
                <div className={styles.section}>
                  <Typography variant="subtitle2" className={styles.sectionTitle}>
                    SCANNED URL
                  </Typography>
                  <div className={styles.urlDisplay}>
                    <Typography variant="body2" component="span">
                      {url}
                    </Typography>
                    <div className={styles.urlActions}>
                      <Tooltip title="Copy URL">
                        <IconButton size="small" onClick={() => copyToClipboard(url)}>
                          <CopyIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Open in new tab">
                        <IconButton size="small" onClick={() => openInNewTab(url)}>
                          <OpenInNewIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </div>
                  </div>
                </div>

                {result.suspicious_factors?.length > 0 && (
                  <div className={styles.suspiciousFactors}>
                    <Typography variant="subtitle2" className={styles.sectionTitle}>
                      SUSPICIOUS FACTORS
                    </Typography>
                    <List dense className={styles.factorList}>
                      {result.suspicious_factors.map((factor, index) => (
                        <ListItem key={index} className={styles.factorItem}>
                          <ListItemIcon className={styles.factorIcon}>
                            <WarningIcon color="warning" fontSize="small" />
                          </ListItemIcon>
                          <ListItemText 
                            primary={factor} 
                            primaryTypographyProps={{ variant: 'body2' }}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </div>
                )}

                <div className={styles.recommendation}>
                  <Typography variant="subtitle2" className={styles.sectionTitle}>
                    RECOMMENDATION
                  </Typography>
                  <Alert 
                    severity={
                      result.isPhishing === true || (result.confidence >= 80) 
                        ? 'error' 
                        : result.is_suspicious === true || (result.confidence >= 55 && result.confidence < 80)
                          ? 'warning' 
                          : 'success'
                    }
                    icon={
                      result.isPhishing === true || (result.confidence >= 80) 
                        ? <WarningIcon /> 
                        : result.is_suspicious === true || (result.confidence >= 55 && result.confidence < 80)
                          ? <WarningIcon /> 
                          : <CheckCircleIcon />
                    }  
                  >
                    {result.isPhishing === true || (result.confidence >= 80)
                      ? 'We strongly recommend not visiting this URL as it appears to be a phishing attempt.'
                      : result.is_suspicious === true || (result.confidence >= 55 && result.confidence < 80)
                        ? 'This URL shows some suspicious characteristics. Proceed with caution and avoid entering personal information.'
                        : 'This URL appears to be safe. However, always be cautious when entering personal information.'
                    }
                    {(result.isPhishing === true || (result.confidence >= 80)) && (
                      <div className={styles.reportButton}>
                        <Button 
                          variant="outlined" 
                          color="error" 
                          size="small"
                          startIcon={<SecurityIcon />}
                          onClick={() => window.open('https://safebrowsing.google.com/safebrowsing/report_phish/', '_blank')}
                        >
                          Report Phishing Site
                        </Button>
                      </div>
                    )}
                  </Alert>
                </div>
              </Paper>
            </Collapse>
          </div>
        </Fade>
      )}

      {/* Error Snackbar */}
      <Snackbar
        open={openSnackbar && !!error}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      >
        <Alert 
          onClose={handleCloseSnackbar} 
          severity="error"
          sx={{ width: '100%' }}
          icon={<ErrorIcon />}
        >
          <AlertTitle>Error</AlertTitle>
          {error}
        </Alert>
      </Snackbar>
    </Paper>
  );
}

export default UrlScanner;