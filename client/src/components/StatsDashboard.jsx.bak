import React, { useCallback, useMemo } from 'react';
import { 
  Box, 
  Paper, 
  Typography, 
  Grid, 
  Card, 
  CardContent, 
  LinearProgress,
  CircularProgress,
  useTheme
} from '@mui/material';
import { 
  Dangerous as DangerousIcon, 
  CheckCircle as CheckCircleIcon,
  Timeline as TimelineIcon,
  Security as SecurityIcon,
  Warning as WarningIcon
} from '@mui/icons-material';
import styles from './StatsDashboard.module.css';
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

// Error boundary component
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error) {
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

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8'];

// StatsCard component
const StatsCard = ({ title, value, icon, color, loading }) => {
  // Memoize the icon class based on color
  const iconClass = useMemo(() => {
    switch (color) {
      case 'error':
        return styles.cardIconError;
      case 'success':
        return styles.cardIconSuccess;
      case 'warning':
        return styles.cardIconWarning;
      default:
        return styles.cardIcon;
    }
  }, [color]);

  // Memoize the rendered content
  const cardContent = useMemo(() => (
    <CardContent className={styles.cardContent}>
      <div className={styles.cardHeader}>
        <div>
          <Typography variant="h6" className={styles.cardTitle}>
            {title}
          </Typography>
          <Typography variant="h4" className={styles.cardValue}>
            {loading ? '...' : value}
          </Typography>
        </div>
        <div className={`${styles.cardIcon} ${iconClass}`}>
          {icon}
        </div>
      </div>
      {loading && <LinearProgress className={styles.progress} />}
    </CardContent>
  ), [title, value, icon, loading, iconClass]);

  return (
    <Card className={styles.card}>
      {cardContent}
    </Card>
  );
};

// Memoize the StatsCard component
const MemoizedStatsCard = React.memo(StatsCard);
StatsCard.displayName = 'StatsCard';

// CustomTooltip component
const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload || !payload.length) return null;
  
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

// PieChartLabel component
const PieChartLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }) => {
  const RADIAN = Math.PI / 180;
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);

  return (
    <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central">
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
};

// Memoize the PieChartLabel
const MemoizedPieChartLabel = React.memo(PieChartLabel);
PieChartLabel.displayName = 'PieChartLabel';

// StatsDashboard component
const StatsDashboard = ({ stats, loading }) => {
  // Defensive: Only use backend-provided stats, never compute or mutate from frontend state
  // If stats is missing or malformed, show error
  if (!stats && !loading) {
    return (
      <div className={styles.errorContainer}>
        <Typography variant="h6" className={styles.errorTitle}>
          Error: No dashboard data received from backend.
        </Typography>
      </div>
    );
  }
  const theme = useTheme();

  // Memoize chart data to prevent unnecessary re-renders
  const { chartData, pieData, detectionRate, lastUpdated } = useMemo(() => {
    // Default values
    const result = {
      chartData: [],
      pieData: [],
      detectionRate: 0,
      lastUpdated: null
    };

    if (!stats) return result;

    // Process chart data
    if (stats.scansByDate) {
      const sortedScans = [...stats.scansByDate].sort((a, b) => 
        new Date(a._id) - new Date(b._id)
      );
      
      result.chartData = sortedScans.map(item => ({
        name: new Date(item._id).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        Phishing: item.phishing || 0,
        Safe: Math.max(0, (item.total - (item.phishing || 0)) || 0),
        Suspicious: item.suspicious || 0,
      }));
    }

    // Process pie chart data
    if (stats.totalScans !== undefined) {
      const phishingCount = stats.phishingScans || 0;
      const suspiciousCount = stats.suspiciousScans || 0;
      const safeCount = Math.max(0, (stats.totalScans - phishingCount - suspiciousCount) || 0);
      
      result.pieData = [
        { name: 'Phishing', value: phishingCount },
        { name: 'Suspicious', value: suspiciousCount },
        { name: 'Safe', value: safeCount },
      ].filter(item => item.value > 0);
      
      // Calculate detection rate
      result.detectionRate = Math.round((phishingCount / stats.totalScans) * 100) || 0;
    }
    
    // Process last updated time
    if (stats.lastUpdated) {
      result.lastUpdated = new Date(stats.lastUpdated).toLocaleTimeString();
    }
    
    return result;
  }, [stats]);
  
  // Memoize the bar chart component
  const renderBarChart = useMemo(() => (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart
        data={chartData}
        margin={{
          top: 5,
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
        <Bar dataKey="Phishing" fill="#f44336" />
        <Bar dataKey="Safe" fill="#4caf50" />
        {chartData.some(d => d.Suspicious > 0) && (
          <Bar dataKey="Suspicious" fill="#ff9800" />
        )}
      </BarChart>
    </ResponsiveContainer>
  ), [chartData]);
  
  // Memoize the pie chart component
  const renderPieChart = useMemo(() => (
    <ResponsiveContainer width="100%" height={300}>
      <PieChart>
        <Pie
          data={pieData}
          cx="50%"
          cy="50%"
          labelLine={false}
          label={MemoizedPieChartLabel}
          outerRadius={80}
          fill="#8884d8"
          dataKey="value"
        >
          {pieData.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
          ))}
        </Pie>
        <Tooltip content={<MemoizedCustomTooltip />} />
        <Legend />
      </PieChart>
    </ResponsiveContainer>
  ), [pieData]);
  
  // Loading state
  if (loading && !stats) {
    return (
      <div className={styles.loadingContainer}>
        <CircularProgress />
      </div>
    );
  }

  // Error state
  if (!stats) {
    return (
      <div className={styles.errorContainer}>
        <Typography variant="h6" className={styles.errorTitle}>
          Error: No data available
        </Typography>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <Typography variant="h5" className={styles.title}>
          Dashboard Overview
        </Typography>
        {lastUpdated && (
          <Typography variant="caption" className={styles.lastUpdated}>
            Last updated: {lastUpdated}
          </Typography>
        )}
      </div>

      {/* Stats Cards */}
      <div className={styles.statsGrid}>
        {/* Total Scans Card */}
        <div className={styles.card}>
          <div className={styles.cardContent}>
            <div className={styles.cardHeader}>
              <div>
                <Typography variant="subtitle2" className={styles.cardTitle}>
                  Total Scans
                </Typography>
                <Typography variant="h4" className={styles.cardValue}>
                  {stats.totalScans.toLocaleString()}
                </Typography>
                <div className={styles.cardDescription}>
                  {Math.round((stats.phishingScans / stats.totalScans) * 100)}% phishing • {Math.round((stats.suspiciousScans / stats.totalScans) * 100)}% suspicious • {Math.round(((stats.totalScans - stats.phishingScans - stats.suspiciousScans) / stats.totalScans) * 100)}% safe
                </div>
              </div>
              <div className={`${styles.cardIcon} ${styles.primaryIcon}`}>
                <TimelineIcon />
              </div>
            </div>
          </div>
        </div>
        <div className={styles.card}>
          <div className={styles.cardContent}>
            <div className={styles.cardHeader}>
              <div>
                <Typography variant="subtitle2" className={styles.cardTitle}>
                  Phishing Detected
                </Typography>
                <Typography variant="h4" className={styles.cardValue}>
                  {stats.phishingScans}
                </Typography>
              </div>
              <div className={`${styles.cardIcon} ${styles.errorIcon}`}>
                <DangerousIcon />
              </div>
            </div>
          </div>
        </div>
        <div className={styles.card}>
          <div className={styles.cardContent}>
            <div className={styles.cardHeader}>
              <div>
                <Typography variant="subtitle2" className={styles.cardTitle}>
                  Suspicious URLs
                </Typography>
                <Typography variant="h4" className={styles.cardValue}>
                  {stats.suspiciousScans}
                </Typography>
              </div>
              <div className={`${styles.cardIcon} ${styles.warningIcon}`}>
                <WarningIcon />
              </div>
            </div>
          </div>
        </div>
        <div className={styles.card}>
          <div className={styles.cardContent}>
            <div className={styles.cardHeader}>
              <div>
                <Typography variant="subtitle2" className={styles.cardTitle}>
                  Safe URLs
                </Typography>
                <Typography variant="h4" className={styles.cardValue}>
                  {stats.totalScans - stats.phishingScans - stats.suspiciousScans}
                </Typography>
              </div>
              <div className={`${styles.cardIcon} ${styles.successIcon}`}>
                <CheckCircleIcon />
              </div>
            </div>
          </div>
        </div>
        <div className={styles.card}>
          <div className={styles.cardContent}>
            <div className={styles.cardHeader}>
              <div>
                <Typography variant="subtitle2" className={styles.cardTitle}>
                  Phishing Detection Rate
                </Typography>
                <Typography variant="h4" className={styles.cardValue}>
                  {Math.round((stats.phishingScans / stats.totalScans) * 100)}%
                </Typography>
              </div>
              <div className={`${styles.cardIcon} ${styles.securityIcon}`}>
                <SecurityIcon />
              </div>
            </div>
          </div>
        </div>
      </div>
            icon={<DangerousIcon />}
            color="error"
            loading={loading}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MemoizedStatsCard
            title="Suspicious URLs"
            value={stats?.suspiciousScans || 0}
            icon={<WarningIcon />}
            color="warning"
            loading={loading}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MemoizedStatsCard
            title="Safe URLs"
            value={(stats?.totalScans - (stats?.phishingScans || 0) - (stats?.suspiciousScans || 0)) || 0}
            icon={<CheckCircleIcon />}
            color="success"
            loading={loading}
          />
        </Grid>
        <Grid item xs={12}>
          <MemoizedStatsCard
            title="Phishing Detection Rate"
            value={`${detectionRate}%`}
            icon={<SecurityIcon />}
            color={detectionRate > 30 ? 'error' : detectionRate > 10 ? 'warning' : 'success'}
            loading={loading}
          />
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3} className={styles.chartsContainer}>
        {/* Bar Chart */}
        <Grid item xs={12} md={8}>
          <Paper className={styles.chartContainer}>
            <Typography variant="h6" className={styles.chartTitle}>
              Scans Over Time
            </Typography>
            <div className={styles.chartWrapper}>
              {renderBarChart}
            </div>
          </Paper>
        </Grid>

        {/* Pie Chart */}
        {pieData.length > 0 && (
          <Grid item xs={12} md={4}>
            <Paper className={styles.chartContainer}>
              <Typography variant="h6" className={styles.chartTitle}>
                Scan Distribution
              </Typography>
              <div className={styles.chartWrapper}>
                {renderPieChart}
              </div>
            </Paper>
          </Grid>
        )}
      </Grid>
    </div>
  );
};

// Add PropTypes for socket
StatsDashboard.propTypes = {
  socket: PropTypes.object,
  stats: PropTypes.shape({
    totalScans: PropTypes.number,
    phishingScans: PropTypes.number,
    safeScans: PropTypes.number,
    scansByDate: PropTypes.arrayOf(
      PropTypes.shape({
        _id: PropTypes.string.isRequired,
        total: PropTypes.number,
        phishing: PropTypes.number
      })
    )
  }),
  loading: PropTypes.bool
};

// Export the memoized component
export default React.memo(StatsDashboard);