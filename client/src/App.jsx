import { useState, useEffect, useCallback } from 'react';
import { 
  Container, 
  CssBaseline, 
  Typography, 
  Box, 
  Snackbar, 
  Alert,
  Button 
} from '@mui/material';
import { CheckCircle, Error } from '@mui/icons-material';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { teal, deepOrange } from '@mui/material/colors';
import { io } from 'socket.io-client';
import UrlScanner from './components/UrlScanner';
import ScanHistory from './components/ScanHistory';
import StatsDashboard from './components/StatsDashboard';
import styles from './App.module.css';

const theme = createTheme({
  palette: {
    primary: teal,
    secondary: deepOrange,
    mode: 'light',
  },
  typography: {
    h3: {
      fontWeight: 600,
      color: teal[800],
    },
  },
});

function App() {
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [socket, setSocket] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [isSearching, setIsSearching] = useState(false);

  // Fetch all scans without pagination
  const fetchScans = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/scans/all');
      if (!response.ok) {
        throw new Error('Failed to fetch scans');
      }
      const data = await response.json();
      setScans(data.scans);
      return { scans: data.scans, total: data.scans.length };
    } catch (error) {
      console.error('Error fetching scans:', error);
      setError('Failed to load scan history. Please try again later.');
      return { scans: [], total: 0 };
    } finally {
      setLoading(false);
    }
  }, []);

  // Fetch statistics with error handling and cache busting
  const fetchStats = useCallback(async () => {
    try {
      const timestamp = new Date().getTime();
      const response = await fetch(`/api/statistics?t=${timestamp}`);
      if (!response.ok) {
        throw new Error('Failed to fetch statistics');
      }
      const data = await response.json();
      setStats(prevStats => ({
        ...prevStats,
        ...data,
        lastUpdated: new Date().toISOString()
      }));
      return data;
    } catch (error) {
      console.error('Error fetching stats:', error);
      setError('Failed to load statistics. Please try again later.');
      return null;
    }
  }, []);

  // Handle new scan updates
  const handleScanUpdate = useCallback(() => {
    fetchStats().catch(console.error);
    fetchScans().catch(console.error);
  }, [fetchStats, fetchScans]);

  // WebSocket connection setup
  useEffect(() => {
    // Safely get the API URL from environment variables with fallback
    let apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000';
    console.log('Initializing WebSocket connection to:', apiUrl);
    
    // Only initialize WebSocket if not already connected
    if (socket && socket.connected) {
      console.log('WebSocket already connected, skipping reinitialization');
      return;
    }
    
    // Configure socket instance with proper options
    const socketInstance = io(apiUrl, {
      // Try WebSocket first, fallback to polling if needed
      transports: ['websocket', 'polling'],
      // Enable auto-connection
      autoConnect: true,
      // Reconnection settings
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      // Timeout settings
      timeout: 10000,
      // Extra headers
      extraHeaders: {
        'X-Client-Type': 'web-client'
      },
      // Disable multiplexing to prevent issues
      multiplex: false,
      // Enable debug logging in development
      forceNew: true
    });

    // Connection event handlers
    const onConnect = () => {
      console.log('✅ WebSocket connected successfully!', socketInstance.id);
      setSocket(socketInstance);
      
      // Update headers with the actual socket ID after connection
      if (socketInstance.io && socketInstance.io.opts) {
        socketInstance.io.opts.extraHeaders = {
          'socket-id': socketInstance.id,
          'X-Client-Type': 'web-client'
        };
      }
    };

    const onConnectError = (error) => {
      console.error('❌ WebSocket connection error:', error.message);
      // Don't manually reconnect - let the socket.io client handle reconnection
    };

    const onDisconnect = (reason) => {
      console.log('ℹ️ WebSocket disconnected:', reason);
      if (reason === 'io server disconnect') {
        // The disconnection was initiated by the server, reconnect after a delay
        setTimeout(() => {
          socketInstance.connect();
        }, 1000);
      }
    };

    // Set up event listeners
    socketInstance.on('connect', onConnect);
    socketInstance.on('connect_error', onConnectError);
    socketInstance.on('disconnect', onDisconnect);

    // Cleanup function
    return () => {
      if (socketInstance) {
        console.log('Cleaning up WebSocket connection');
        socketInstance.off('connect', onConnect);
        socketInstance.off('connect_error', onConnectError);
        socketInstance.off('disconnect', onDisconnect);
        socketInstance.disconnect();
      }
    };

    const handleError = (error) => {
      console.error('WebSocket error:', error);
      setError('Connection error. Some features may not work as expected.');
    };

    const handleScanUpdateEvent = (data) => {
      // Only process updates that don't originate from this client
      if (data.originSocketId !== socketInstance.id) {
        console.log('Received scan update from another client:', data);
        handleScanUpdate();
      } else {
        console.log('Ignoring self-originated scan update');
      }
    };

    socketInstance.on('connect', handleConnect);
    socketInstance.on('disconnect', handleDisconnect);
    socketInstance.on('error', handleError);
    socketInstance.on('scanUpdate', handleScanUpdateEvent);

    setSocket(socketInstance);

    return () => {
      socketInstance.off('connect', handleConnect);
      socketInstance.off('disconnect', handleDisconnect);
      socketInstance.off('error', handleError);
      socketInstance.off('scanUpdate', handleScanUpdateEvent);
      socketInstance.disconnect();
    };
  }, [handleScanUpdate]);

  // Initial data load
  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        await Promise.all([fetchStats(), fetchScans()]);
      } catch (error) {
        console.error('Error loading initial data:', error);
        setError('Failed to load initial data. Please refresh the page.');
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, [fetchScans, fetchStats]);

  // Handle page changes for pagination
  const handlePageChange = useCallback((event, newPage) => {
    fetchScans(newPage + 1).catch(console.error);
  }, [fetchScans]);

  // Handle search functionality
  const handleSearch = useCallback((term) => {
    setSearchTerm(term);
    setIsSearching(!!term);
    
    if (term) {
      setScans(prevScans => 
        prevScans.filter(scan => 
          scan.url.toLowerCase().includes(term.toLowerCase()) ||
          (scan.domain && scan.domain.toLowerCase().includes(term.toLowerCase()))
        )
      );
    } else {
      fetchScans().catch(console.error);
    }
  }, [fetchScans]);

  // Handle closing error alerts
  const handleCloseError = useCallback(() => {
    setError(null);
  }, []);

  // Extract domain from URL
  const getDomainFromUrl = (url) => {
    if (!url) return '';
    try {
      const { hostname } = new URL(url);
      return hostname.replace(/^www\./i, '');
    } catch (e) {
      return url
        .replace(/^https?:\/\//i, '')
        .replace(/^www\./i, '')
        .split(/[\/?#]/)[0];
    }
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Container maxWidth="lg" className={styles.container}>
        {/* WebSocket Status */}
        <Box sx={{ position: 'fixed', bottom: 16, right: 16, zIndex: 1000 }}>
          <Button 
            variant="contained" 
            color={socket?.connected ? 'success' : 'error'}
            onClick={() => {
              if (socket) {
                socket.emit('test-connection', { test: 'Connection test' }, (response) => {
                  console.log('Test response:', response);
                  setSnackbar({
                    open: true,
                    message: `WebSocket Test: ${response.status}`,
                    severity: 'success'
                  });
                });
              } else {
                setSnackbar({
                  open: true,
                  message: 'WebSocket not connected',
                  severity: 'error'
                });
              }
            }}
            startIcon={socket?.connected ? <CheckCircle /> : <Error />}
          >
            {socket?.connected ? 'Connected' : 'Disconnected'}
          </Button>
        </Box>

        {/* Error Alert */}
        {error && (
          <Snackbar
            open={!!error}
            autoHideDuration={6000}
            onClose={handleCloseError}
            anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
          >
            <Alert onClose={handleCloseError} severity="error" sx={{ width: '100%' }}>
              {error}
            </Alert>
          </Snackbar>
        )}

        {/* URL Scanner */}
        <Box className={styles.section}>
          <UrlScanner onNewScan={handleScanUpdate} />
        </Box>

        {/* Stats Dashboard */}
        <Box className={styles.section}>
          <StatsDashboard 
            stats={stats} 
            loading={loading} 
            socket={socket} 
          />
        </Box>


        {/* Scan History */}
        <Box className={styles.section}>
          <ScanHistory
            scans={scans}
            loading={loading}
            onSearch={handleSearch}
            onPageChange={handlePageChange}
          />
        </Box>
      </Container>
    </ThemeProvider>
  );
}

export default App;
