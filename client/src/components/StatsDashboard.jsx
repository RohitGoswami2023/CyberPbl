import React, { useState, useEffect, useMemo } from 'react';
import { 
  Typography, 
  CircularProgress,
  Paper,
  Card,
  CardContent,
  LinearProgress
} from '@mui/material';
import { 
  Dangerous as DangerousIcon, 
  CheckCircle as CheckCircleIcon,
  Timeline as TimelineIcon,
  Warning as WarningIcon
} from '@mui/icons-material';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer,
  PieChart, 
  Pie, 
  Cell
} from 'recharts';
import PropTypes from 'prop-types';
import styles from './StatsDashboard.module.css';

// Error boundary component
class ErrorBoundary extends React.Component {
  state = { hasError: false };

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Dashboard Error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className={styles.errorContainer}>
          <Typography variant="h6" className={styles.errorTitle}>
            Something went wrong. Please refresh the page.
          </Typography>
        </div>
      );
    }
    return this.props.children;
  }
}

// Color scheme for charts
const COLORS = {
  phishing: '#f44336',
  suspicious: '#ff9800',
  safe: '#4caf50',
  primary: '#3f51b5',
  active: '#2196f3'
};

// StatsCard component
const StatsCard = ({ title, value, icon, color, description, loading = false }) => (
  <Card className={styles.card}>
    <CardContent className={styles.cardContent}>
      <div className={styles.cardHeader}>
        <div>
          <Typography variant="subtitle2" className={styles.cardTitle}>
            {title}
          </Typography>
          <Typography variant="h4" className={styles.cardValue}>
            {loading ? '...' : value}
          </Typography>
          {description && (
            <Typography variant="caption" className={styles.cardDescription}>
              {description}
            </Typography>
          )}
        </div>
        <div className={`${styles.cardIcon} ${styles[`${color}Icon`]}`}>
          {icon}
        </div>
      </div>
      {loading && <LinearProgress />}
    </CardContent>
  </Card>
);

// Memoize the StatsCard component
const MemoizedStatsCard = React.memo(StatsCard);

// Custom Tooltip for charts
const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  
  return (
    <Paper className={styles.tooltip} elevation={3}>
      <Typography variant="body2" className={styles.tooltipLabel}>
        {label}
      </Typography>
      {payload.map((entry, index) => (
        <Typography 
          key={`tooltip-${index}`}
          variant="body2" 
          className={styles.tooltipValue}
          style={{ color: entry.color }}
        >
          {`${entry.name}: ${entry.value}`}
        </Typography>
      ))}
    </Paper>
  );
};

// Memoize the CustomTooltip
const MemoizedCustomTooltip = React.memo(CustomTooltip);

// Main StatsDashboard component
const StatsDashboard = ({ stats, socket, loading = false }) => {
  const [lastUpdate, setLastUpdate] = useState(new Date());
  const [error, setError] = useState(null);

  // WebSocket event handlers
  useEffect(() => {
    if (!socket) return;

    const onConnect = () => {
      console.log('WebSocket connected');
      setLastUpdate(new Date());
    };

    const onDisconnect = () => {
      console.log('WebSocket disconnected');
    };

    const onError = (error) => {
      console.error('WebSocket error:', error);
      setError('Connection error. Some features may not work as expected.');
    };

    const onScanUpdate = (data) => {
      console.log('Received scan update:', data);
      setLastUpdate(new Date());
    };

    // Set up event listeners
    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('error', onError);
    socket.on('scanUpdate', onScanUpdate);

    // Clean up event listeners
    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('error', onError);
      socket.off('scanUpdate', onScanUpdate);
    };
  }, [socket]);

  // Calculate statistics
  const totalScans = stats?.totalScans || 0;
  const phishingScans = stats?.phishingScans || 0;
  const safeScans = Math.max(0, totalScans - phishingScans);
  
  // Calculate percentages
  const phishingPercent = totalScans > 0 ? Math.round((phishingScans / totalScans) * 100) : 0;
  const safePercent = totalScans > 0 ? Math.round((safeScans / totalScans) * 100) : 0;
  
  // Data for charts
  const statusData = [
    { name: 'Phishing', value: phishingScans, color: COLORS.phishing },
    { name: 'Safe', value: safeScans, color: COLORS.safe }
  ];


  // Process historical data for charts if available
  const chartData = React.useMemo(() => {
    if (!stats?.scansByDate?.length) return [];
    
    return [...stats.scansByDate]
      .sort((a, b) => new Date(a._id) - new Date(b._id))
      .map(item => ({
        name: new Date(item._id).toLocaleDateString('en-US', { 
          month: 'short', 
          day: 'numeric' 
        }),
        Phishing: item.phishing || 0,
        Safe: Math.max(0, (item.total - (item.phishing || 0)) || 0)
      }));
  }, [stats?.scansByDate]);
  
  // Show loading state
  if (loading) {
    return (
      <div className={styles.loadingContainer}>
        <CircularProgress />
        <Typography variant="body1" className={styles.loadingText}>
          Loading dashboard data...
        </Typography>
      </div>
    );
  }
  
  // Show error state if no stats available
  if (!stats) {
    return (
      <div className={styles.errorContainer}>
        <Typography variant="h6" className={styles.errorTitle}>
          Error: Unable to load dashboard data. Please try again later.
        </Typography>
        {error && (
          <Typography variant="body2" className={styles.errorMessage}>
            {error}
          </Typography>
        )}
      </div>
    );
  }

  return (
    <ErrorBoundary>
      <div className={styles.container}>
        <div className={styles.header}>
          <div>
            <Typography variant="h5" className={styles.title}>
              Dashboard Overview
            </Typography>
            <div className={styles.statusBar}>
              <span className={styles.lastUpdated}>
                Last updated: {lastUpdate.toLocaleTimeString()}
              </span>
            </div>
          </div>
        </div>

        <div className={styles.statsGrid}>
          {/* Total Scans Card */}
          <MemoizedStatsCard
            title="Total Scans"
            value={totalScans.toLocaleString()}
            icon={<TimelineIcon />}
            color="primary"
            description={`${phishingPercent}% phishing • ${safePercent}% safe`}
            loading={loading}
          />

          {/* Phishing Detected Card */}
          <MemoizedStatsCard
            title="Phishing Detected"
            value={phishingScans}
            icon={<DangerousIcon />}
            color="error"
            description={`${phishingPercent}% of all scans`}
            loading={loading}
          />

          {/* Safe URLs Card */}
          <MemoizedStatsCard
            title="Safe URLs"
            value={safeScans}
            icon={<CheckCircleIcon />}
            color="success"
            description={`${safePercent}% of all scans`}
            loading={loading}
          />
        </div>

        <div className={styles.chartsContainer}>
          {/* Status Distribution Pie Chart */}
          <div className={styles.chartContainer}>
            <Typography variant="h6" className={styles.chartTitle}>
              URL Status Distribution
            </Typography>
            <div className={styles.chartWrapper}>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={statusData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  >
                    {statusData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<MemoizedCustomTooltip />} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Historical Data Line Chart */}
          {chartData.length > 0 && (
            <div className={styles.chartContainer} style={{ gridColumn: '1 / -1' }}>
              <Typography variant="h6" className={styles.chartTitle}>
                Scan History
              </Typography>
              <div className={styles.chartWrapper}>
                <ResponsiveContainer width="100%" height={400}>
                  <BarChart
                    data={chartData}
                    margin={{
                      top: 20,
                      right: 30,
                      left: 20,
                      bottom: 5,
                    }}
                  >
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip content={<MemoizedCustomTooltip />} />
                    <Legend />
                    <Bar dataKey="Phishing" stackId="a" fill={COLORS.phishing} />
                    <Bar dataKey="Suspicious" stackId="a" fill={COLORS.suspicious} />
                    <Bar dataKey="Safe" stackId="a" fill={COLORS.safe} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </div>
      </div>
    </ErrorBoundary>
  );
};

// Prop types
StatsDashboard.propTypes = {
  stats: PropTypes.shape({
    totalScans: PropTypes.number,
    phishingScans: PropTypes.number,
    suspiciousScans: PropTypes.number,
    scansByDate: PropTypes.arrayOf(
      PropTypes.shape({
        _id: PropTypes.string,
        total: PropTypes.number,
        phishing: PropTypes.number,
        suspicious: PropTypes.number
      })
    )
  }),
  loading: PropTypes.bool,
  socket: PropTypes.object
};

// Default props
StatsDashboard.defaultProps = {
  stats: null,
  loading: false,
  socket: null
};

export default StatsDashboard;
