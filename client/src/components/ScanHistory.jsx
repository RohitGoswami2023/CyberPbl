import React, { useState } from 'react';
import PropTypes from 'prop-types';
import { 
  Paper, 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow, 
  Typography,
  Chip,
  LinearProgress,
  Box,
  TablePagination,
  IconButton,
  Tooltip,
  TextField,
  InputAdornment,
  CircularProgress,
  useTheme,
  styled,
  tableCellClasses
} from '@mui/material';
import { 
  Dangerous as DangerousIcon, 
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Link as LinkIcon,
  Search as SearchIcon,
  FirstPage as FirstPageIcon,
  LastPage as LastPageIcon,
  KeyboardArrowLeft,
  KeyboardArrowRight
} from '@mui/icons-material';
import styles from './ScanHistory.module.css';

function TablePaginationActions(props) {
  const theme = useTheme();
  const { count, page, rowsPerPage, onPageChange } = props;

  const handleFirstPageButtonClick = (event) => {
    onPageChange(event, 0);
  };

  const handleBackButtonClick = (event) => {
    onPageChange(event, page - 1);
  };

  const handleNextButtonClick = (event) => {
    onPageChange(event, page + 1);
  };

  const handleLastPageButtonClick = (event) => {
    onPageChange(event, Math.max(0, Math.ceil(count / rowsPerPage) - 1));
  };

  return (
    <Box sx={{ flexShrink: 0, ml: 2.5 }}>
      <IconButton
        onClick={handleFirstPageButtonClick}
        disabled={page === 0}
        aria-label="first page"
      >
        {theme.direction === 'rtl' ? <LastPageIcon /> : <FirstPageIcon />}
      </IconButton>
      <IconButton
        onClick={handleBackButtonClick}
        disabled={page === 0}
        aria-label="previous page"
      >
        {theme.direction === 'rtl' ? <KeyboardArrowRight /> : <KeyboardArrowLeft />}
      </IconButton>
      <IconButton
        onClick={handleNextButtonClick}
        disabled={page >= Math.ceil(count / rowsPerPage) - 1}
        aria-label="next page"
      >
        {theme.direction === 'rtl' ? <KeyboardArrowLeft /> : <KeyboardArrowRight />}
      </IconButton>
      <IconButton
        onClick={handleLastPageButtonClick}
        disabled={page >= Math.ceil(count / rowsPerPage) - 1}
        aria-label="last page"
      >
        {theme.direction === 'rtl' ? <FirstPageIcon /> : <LastPageIcon />}
      </IconButton>
    </Box>
  );
}

TablePaginationActions.propTypes = {
  count: PropTypes.number.isRequired,
  onPageChange: PropTypes.func.isRequired,
  page: PropTypes.number.isRequired,
  rowsPerPage: PropTypes.number.isRequired,
};

const StyledTableRow = styled(TableRow)(({ theme }) => ({
  '&:nth-of-type(odd)': {
    backgroundColor: theme.palette.action.hover,
  },
  '&:last-child td, &:last-child th': {
    border: 0,
  },
}));

const ScanHistory = ({ scans = [], loading = false, onSearch, onPageChange }) => {
  // Defensive: Only use backend-provided scan data
  if (!loading && (!scans || !Array.isArray(scans))) {
    return (
      <Paper className={styles.container}>
        <Typography variant="h6" className={styles.errorTitle}>
          Error: No scan history data received from backend.
        </Typography>
      </Paper>
    );
  }
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [searchTerm, setSearchTerm] = useState('');

  const handleChangePage = (event, newPage) => {
    setPage(newPage);
    if (onPageChange) {
      onPageChange(newPage + 1, rowsPerPage);
    }
  };

  const handleChangeRowsPerPage = (event) => {
    const newRowsPerPage = parseInt(event.target.value, 10);
    setRowsPerPage(newRowsPerPage);
    setPage(0);
    if (onPageChange) {
      onPageChange(1, newRowsPerPage);
    }
  };

  const handleSearch = (e) => {
    const value = e.target.value;
    setSearchTerm(value);
    if (onSearch) {
      onSearch(value);
    }
    setPage(0);
  };

  const formatDate = (dateString) => {
    try {
      // Handle both string timestamps and Date objects
      const date = new Date(dateString);
      if (isNaN(date.getTime())) {
        return 'N/A';
      }
      // Format: DD/MM/YYYY, HH:MM:SS
      return date.toLocaleString('en-IN', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
      });
    } catch (e) {
      console.error('Error formatting date:', e);
      return 'N/A';
    }
  };

  // Format number to exactly 2 decimal places without thousands separators
  const formatNumber = (num) => {
    if (num === null || num === undefined) return 'N/A';
    // Convert to number if it's a string
    let number = typeof num === 'string' ? parseFloat(num) : num;
    if (isNaN(number)) return 'N/A';
    
    // If the number is greater than 1, assume it's a percentage and divide by 100
    if (number > 1) {
      number = number / 100;
    }
    
    // Format to exactly 2 decimal places and ensure it's a percentage
    return (number * 100).toFixed(2);
  };

  // Get status information for a scan
  const getStatusInfo = (scan) => {
    const confidence = typeof scan.confidence === 'number' ? scan.confidence : 
                     (typeof scan.confidence === 'string' ? parseFloat(scan.confidence) : 0);
    
    const isPhishing = scan.isPhishing === true || scan.isPhishing === 'true';
    const isSuspicious = (scan.is_suspicious === true || scan.is_suspicious === 'true' || 
                         (confidence >= 40 && confidence < 70)) && !isPhishing;
    
    let status = 'safe';
    let label = 'Safe';
    let color = 'success';
    let icon = <CheckCircleIcon />;
    let tooltip = 'This URL appears to be safe (0-40% confidence)';
    
    if (isPhishing) {
      status = 'phishing';
      label = 'Phishing';
      color = 'error';
      icon = <DangerousIcon />;
      tooltip = '⚠️ High Risk: This URL is likely a phishing site (70-100% confidence)';
    } else if (isSuspicious) {
      status = 'suspicious';
      label = 'Suspicious';
      color = 'warning';
      icon = <WarningIcon />;
      tooltip = '⚠️ Medium Risk: This URL shows suspicious characteristics (40-70% confidence)';
    }
    
    // Add reason to tooltip if available
    if (scan.reason) {
      tooltip += `\n\nReason: ${scan.reason}`;
    }
    
    // Add confidence to tooltip
    tooltip += `\nConfidence: ${formatNumber(confidence)}%`;
    
    return { status, label, color, icon, tooltip, confidence };
  };

  return (
    <Paper elevation={3} className={styles.container}>
      <div className={styles.header}>
        <Typography variant="h5" className={styles.title}>
          Scan History
        </Typography>
        <TextField
          size="small"
          placeholder="Search scans..."
          value={searchTerm}
          onChange={handleSearch}
          className={styles.searchField}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon />
              </InputAdornment>
            ),
          }}
        />
      </div>

      <TableContainer className={styles.tableContainer}>
        <Table className={styles.table}>
          <TableHead>
            <TableRow className={styles.tableHead}>
              <TableCell>URL</TableCell>
              <TableCell align="center">Status</TableCell>
              <TableCell align="center">Confidence</TableCell>
              <TableCell>Domain</TableCell>
              <TableCell>Date</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={5} align="center" className={styles.loadingContainer}>
                  <CircularProgress />
                  <Typography variant="body2" className={styles.loadingText}>
                    Loading scan history...
                  </Typography>
                </TableCell>
              </TableRow>
            ) : !scans || scans.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} align="center" className={styles.emptyState}>
                  <Typography variant="body1">
                    No scan history available
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              scans.map((scan) => (
                <StyledTableRow key={scan._id || Math.random().toString(36).substr(2, 9)} className={styles.tableRow} hover>
                  <TableCell>
                    <div className={styles.urlCell}>
                      <LinkIcon color="action" className={styles.statusIcon} />
                      <Tooltip title={scan.url} placement="top" className={styles.tooltip}>
                        <span className={styles.urlText}>
                          {scan.url || 'N/A'}
                        </span>
                      </Tooltip>
                    </div>
                  </TableCell>
                  <TableCell align="center">
                    {(() => {
                    const statusInfo = getStatusInfo(scan);
                    return (
                      <Tooltip 
                        title={
                          <div style={{ whiteSpace: 'pre-line' }}>
                            {statusInfo.tooltip}
                          </div>
                        }
                        arrow
                        placement="top"
                        enterDelay={300}
                      >
                        <Chip
                          icon={statusInfo.icon}
                          label={statusInfo.label}
                          onClick={(e) => e.stopPropagation()}
                          component="span"
                          color={statusInfo.color}
                          size="small"
                          variant="outlined"
                          className={styles.statusChip}
                        />
                      </Tooltip>
                    );
                  })()}
                  </TableCell>
                  <TableCell align="center">
                    <Tooltip 
                      title={`Confidence: ${formatNumber(scan.confidence)}%`}
                      arrow
                      placement="top"
                    >
                      <div className={styles.confidenceContainer}>
                        <div className={styles.confidenceBar}>
                          <div 
                            className={`${styles.confidenceFill} ${
                              getStatusInfo(scan).status === 'phishing' 
                                ? styles.error 
                                : getStatusInfo(scan).status === 'suspicious'
                                  ? styles.warning 
                                  : styles.success
                            }`}
                            style={{ 
                              width: `${Math.min(100, Math.max(0, scan.confidence || 0)).toFixed(0)}%`,
                              transition: 'width 0.3s ease-in-out'
                            }}
                          />
                        </div>
                        <Typography 
                          variant="body2" 
                          className={`${styles.confidenceText} ${
                            getStatusInfo(scan).status === 'phishing' 
                              ? styles.errorText 
                              : getStatusInfo(scan).status === 'suspicious'
                                ? styles.warningText 
                                : styles.successText
                          }`}
                        >
                          {scan.confidence !== undefined ? `${formatNumber(scan.confidence)}%` : 'N/A'}
                        </Typography>
                      </div>
                    </Tooltip>
                  </TableCell>
                  <TableCell>{scan.domain || 'N/A'}</TableCell>
                  <TableCell className={styles.dateCell}>{formatDate(scan.timestamp)}</TableCell>
                </StyledTableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {!loading && scans && scans.length > 0 && (
        <div className={styles.pagination}>
          <TablePagination
            rowsPerPageOptions={[5, 10, 25, 50]}
            component="div"
            count={scans.length}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            ActionsComponent={TablePaginationActions}
            sx={{
              '.MuiTablePagination-toolbar': {
                paddingRight: 2,
              },
              '.MuiTablePagination-selectLabel, .MuiTablePagination-displayedRows': {
                marginBottom: 0,
              },
            }}
          />
        </div>
      )}
    </Paper>
  );
};

export default ScanHistory;