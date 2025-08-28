import { clsx } from 'clsx'
import { format, subDays } from 'date-fns'
import { AnimatePresence, motion } from 'framer-motion'
import {
    Activity,
    AlertCircle,
    AlertTriangle,
    BarChart3,
    CheckCircle,
    Clock,
    Eye,
    Globe,
    Info,
    Network,
    RefreshCw,
    Search,
    Shield,
    Target,
    TrendingUp,
    XCircle,
    Zap
} from 'lucide-react'
import Head from 'next/head'
import { useEffect, useState } from 'react'
import { toast, Toaster } from 'react-hot-toast'
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

interface Alert {
    id: string
    alert_data: {
        title: string
        description: string
        source: string
        severity: string
        tags: string[]
        cve_id?: string
        cvss_score?: number
        published_at?: string
        iocs?: Array<{ type: string; value: string }>
    }
    priority_score: number
    timestamp: string
    status: string
    severity: string
    source: string
    tags: string[]
}

interface DashboardData {
    recent_alerts: number
    critical_alerts: number
    high_alerts: number
    top_sources: [string, number][]
    last_updated: string
    alerts_timeline: Array<{ date: string; count: number }>
    severity_distribution: Array<{ name: string; value: number; color: string }>
    source_distribution: Array<{ name: string; value: number }>
}

interface Statistics {
    total_alerts: number
    monthly_alerts: number
    severity_distribution: {
        low: number
        medium: number
        high: number
        critical: number
    }
    last_updated: string
}

const COLORS = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
    info: '#3b82f6'
}

export default function Home() {
    const [alerts, setAlerts] = useState<Alert[]>([])
    const [dashboardData, setDashboardData] = useState<DashboardData | null>(null)
    const [statistics, setStatistics] = useState<Statistics | null>(null)
    const [loading, setLoading] = useState(true)
    const [refreshing, setRefreshing] = useState(false)
    const [filters, setFilters] = useState({
        severity: '',
        source: '',
        tags: [] as string[]
    })
    const [searchTerm, setSearchTerm] = useState('')
    const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
    const [viewMode, setViewMode] = useState<'dashboard' | 'alerts'>('dashboard')

    const CLOUD_FUNCTION_URL = process.env.NEXT_PUBLIC_CLOUD_FUNCTION_URL || 'http://localhost:8080'

    useEffect(() => {
        fetchDashboardData()
        fetchAlerts()
        fetchStatistics()
    }, [])

    const fetchDashboardData = async () => {
        try {
            const response = await fetch(`${CLOUD_FUNCTION_URL}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'get_dashboard' })
            })
            const data = await response.json()
            setDashboardData(data)
        } catch (error) {
            console.error('Error fetching dashboard data:', error)
            toast.error('Error loading dashboard data')
        }
    }

    const fetchAlerts = async () => {
        try {
            const response = await fetch(`${CLOUD_FUNCTION_URL}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'get_alerts',
                    filters,
                    limit: 50,
                    offset: 0
                })
            })
            const data = await response.json()
            setAlerts(data.alerts || [])
        } catch (error) {
            console.error('Error fetching alerts:', error)
            toast.error('Error loading alerts')
        } finally {
            setLoading(false)
        }
    }

    const fetchStatistics = async () => {
        try {
            const response = await fetch(`${CLOUD_FUNCTION_URL}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'get_statistics' })
            })
            const data = await response.json()
            setStatistics(data)
        } catch (error) {
            console.error('Error fetching statistics:', error)
            toast.error('Error loading statistics')
        }
    }

    const triggerCollection = async () => {
        setRefreshing(true)
        const loadingToast = toast.loading('Collecting new alerts...')

        try {
            const response = await fetch('/api/collect', { method: 'POST' })
            const data = await response.json()

            // Refresh all data
            await Promise.all([
                fetchDashboardData(),
                fetchAlerts(),
                fetchStatistics()
            ])

            toast.success(`Collection completed: ${data.alerts_processed} new alerts processed`, {
                id: loadingToast
            })
        } catch (error) {
            console.error('Error triggering collection:', error)
            toast.error('Error triggering collection', {
                id: loadingToast
            })
        } finally {
            setRefreshing(false)
        }
    }

    const getSeverityColor = (severity: string) => {
        switch (severity.toLowerCase()) {
            case 'critical': return 'bg-red-100 text-red-800 border-red-200'
            case 'high': return 'bg-orange-100 text-orange-800 border-orange-200'
            case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200'
            case 'low': return 'bg-green-100 text-green-800 border-green-200'
            default: return 'bg-gray-100 text-gray-800 border-gray-200'
        }
    }

    const getPriorityColor = (score: number) => {
        if (score >= 8) return 'text-red-600'
        if (score >= 6) return 'text-orange-600'
        if (score >= 4) return 'text-yellow-600'
        return 'text-green-600'
    }

    const getStatusIcon = (severity: string) => {
        switch (severity.toLowerCase()) {
            case 'critical': return <XCircle className="h-5 w-5 text-red-500" />
            case 'high': return <AlertTriangle className="h-5 w-5 text-orange-500" />
            case 'medium': return <Info className="h-5 w-5 text-yellow-500" />
            case 'low': return <CheckCircle className="h-5 w-5 text-green-500" />
            default: return <Info className="h-5 w-5 text-gray-500" />
        }
    }

    const filteredAlerts = alerts.filter(alert => {
        const matchesSearch = searchTerm === '' ||
            alert.alert_data.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
            alert.alert_data.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
            alert.alert_data.source.toLowerCase().includes(searchTerm.toLowerCase())

        const matchesSeverity = filters.severity === '' || alert.severity === filters.severity
        const matchesSource = filters.source === '' || alert.source === filters.source

        return matchesSearch && matchesSeverity && matchesSource
    })

    // Mock data for charts (replace with real data from API)
    const timelineData = Array.from({ length: 7 }, (_, i) => ({
        date: format(subDays(new Date(), 6 - i), 'MMM dd'),
        alerts: Math.floor(Math.random() * 20) + 5,
        threats: Math.floor(Math.random() * 10) + 2
    }))

    const severityData = [
        { name: 'Critical', value: statistics?.severity_distribution.critical || 0, color: COLORS.critical },
        { name: 'High', value: statistics?.severity_distribution.high || 0, color: COLORS.high },
        { name: 'Medium', value: statistics?.severity_distribution.medium || 0, color: COLORS.medium },
        { name: 'Low', value: statistics?.severity_distribution.low || 0, color: COLORS.low }
    ]

    return (
        <>
            <Head>
                <title>C4A Alerts - Threat Intelligence Platform</title>
                <meta name="description" content="Advanced threat intelligence and monitoring platform" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <link rel="icon" href="/favicon.ico" />
            </Head>

            <Toaster position="top-right" />

            <main className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
                {/* Header */}
                <header className="bg-white/80 backdrop-blur-sm shadow-sm border-b border-gray-200 sticky top-0 z-50">
                    <div className="container mx-auto px-4 py-4">
                        <div className="flex justify-between items-center">
                            <div className="flex items-center space-x-3">
                                <div className="relative">
                                    <Shield className="h-8 w-8 text-blue-600" />
                                    <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
                                </div>
                                <div>
                                    <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                                        C4A Alerts
                                    </h1>
                                    <p className="text-sm text-gray-500">Threat Intelligence Platform</p>
                                </div>
                            </div>

                            <div className="flex items-center space-x-4">
                                <div className="flex space-x-2">
                                    <button
                                        onClick={() => setViewMode('dashboard')}
                                        className={clsx(
                                            "px-4 py-2 rounded-lg font-medium transition-all",
                                            viewMode === 'dashboard'
                                                ? "bg-blue-600 text-white shadow-lg"
                                                : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                                        )}
                                    >
                                        Dashboard
                                    </button>
                                    <button
                                        onClick={() => setViewMode('alerts')}
                                        className={clsx(
                                            "px-4 py-2 rounded-lg font-medium transition-all",
                                            viewMode === 'alerts'
                                                ? "bg-blue-600 text-white shadow-lg"
                                                : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                                        )}
                                    >
                                        Alerts
                                    </button>
                                </div>

                                <button
                                    onClick={triggerCollection}
                                    disabled={refreshing}
                                    className="flex items-center space-x-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 disabled:opacity-50 text-white px-6 py-2 rounded-lg font-medium transition-all shadow-lg hover:shadow-xl"
                                >
                                    {refreshing ? (
                                        <RefreshCw className="h-4 w-4 animate-spin" />
                                    ) : (
                                        <Zap className="h-4 w-4" />
                                    )}
                                    <span>{refreshing ? 'Collecting...' : 'Collect Alerts'}</span>
                                </button>
                            </div>
                        </div>
                    </div>
                </header>

                <div className="container mx-auto px-4 py-8">
                    <AnimatePresence mode="wait">
                        {viewMode === 'dashboard' ? (
                            <motion.div
                                key="dashboard"
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -20 }}
                                transition={{ duration: 0.3 }}
                            >
                                {/* Dashboard Stats Cards */}
                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                                    <motion.div
                                        initial={{ opacity: 0, scale: 0.9 }}
                                        animate={{ opacity: 1, scale: 1 }}
                                        transition={{ delay: 0.1 }}
                                        className="bg-white/80 backdrop-blur-sm p-6 rounded-xl shadow-lg border border-gray-200 hover:shadow-xl transition-all"
                                    >
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <p className="text-sm font-medium text-gray-600">Total Alerts</p>
                                                <p className="text-3xl font-bold text-gray-900">{statistics?.total_alerts || 0}</p>
                                            </div>
                                            <div className="p-3 bg-blue-100 rounded-lg">
                                                <AlertTriangle className="h-8 w-8 text-blue-600" />
                                            </div>
                                        </div>
                                        <div className="mt-4 flex items-center text-sm text-green-600">
                                            <TrendingUp className="h-4 w-4 mr-1" />
                                            <span>+12% from last week</span>
                                        </div>
                                    </motion.div>

                                    <motion.div
                                        initial={{ opacity: 0, scale: 0.9 }}
                                        animate={{ opacity: 1, scale: 1 }}
                                        transition={{ delay: 0.2 }}
                                        className="bg-white/80 backdrop-blur-sm p-6 rounded-xl shadow-lg border border-gray-200 hover:shadow-xl transition-all"
                                    >
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <p className="text-sm font-medium text-gray-600">Critical Threats</p>
                                                <p className="text-3xl font-bold text-red-600">{dashboardData?.critical_alerts || 0}</p>
                                            </div>
                                            <div className="p-3 bg-red-100 rounded-lg">
                                                <XCircle className="h-8 w-8 text-red-600" />
                                            </div>
                                        </div>
                                        <div className="mt-4 flex items-center text-sm text-red-600">
                                            <AlertCircle className="h-4 w-4 mr-1" />
                                            <span>Requires immediate action</span>
                                        </div>
                                    </motion.div>

                                    <motion.div
                                        initial={{ opacity: 0, scale: 0.9 }}
                                        animate={{ opacity: 1, scale: 1 }}
                                        transition={{ delay: 0.3 }}
                                        className="bg-white/80 backdrop-blur-sm p-6 rounded-xl shadow-lg border border-gray-200 hover:shadow-xl transition-all"
                                    >
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <p className="text-sm font-medium text-gray-600">Active Sources</p>
                                                <p className="text-3xl font-bold text-purple-600">{dashboardData?.top_sources?.length || 0}</p>
                                            </div>
                                            <div className="p-3 bg-purple-100 rounded-lg">
                                                <Globe className="h-8 w-8 text-purple-600" />
                                            </div>
                                        </div>
                                        <div className="mt-4 flex items-center text-sm text-purple-600">
                                            <Network className="h-4 w-4 mr-1" />
                                            <span>Monitoring active</span>
                                        </div>
                                    </motion.div>

                                    <motion.div
                                        initial={{ opacity: 0, scale: 0.9 }}
                                        animate={{ opacity: 1, scale: 1 }}
                                        transition={{ delay: 0.4 }}
                                        className="bg-white/80 backdrop-blur-sm p-6 rounded-xl shadow-lg border border-gray-200 hover:shadow-xl transition-all"
                                    >
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <p className="text-sm font-medium text-gray-600">Response Time</p>
                                                <p className="text-3xl font-bold text-green-600">2.3s</p>
                                            </div>
                                            <div className="p-3 bg-green-100 rounded-lg">
                                                <Activity className="h-8 w-8 text-green-600" />
                                            </div>
                                        </div>
                                        <div className="mt-4 flex items-center text-sm text-green-600">
                                            <CheckCircle className="h-4 w-4 mr-1" />
                                            <span>Optimal performance</span>
                                        </div>
                                    </motion.div>
                                </div>

                                {/* Charts Section */}
                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
                                    {/* Timeline Chart */}
                                    <motion.div
                                        initial={{ opacity: 0, x: -20 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        transition={{ delay: 0.5 }}
                                        className="bg-white/80 backdrop-blur-sm p-6 rounded-xl shadow-lg border border-gray-200"
                                    >
                                        <h3 className="text-lg font-semibold text-gray-900 mb-4">Alerts Timeline</h3>
                                        <ResponsiveContainer width="100%" height={300}>
                                            <AreaChart data={timelineData}>
                                                <CartesianGrid strokeDasharray="3 3" />
                                                <XAxis dataKey="date" />
                                                <YAxis />
                                                <Tooltip />
                                                <Area type="monotone" dataKey="alerts" stackId="1" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.6} />
                                                <Area type="monotone" dataKey="threats" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.6} />
                                            </AreaChart>
                                        </ResponsiveContainer>
                                    </motion.div>

                                    {/* Severity Distribution */}
                                    <motion.div
                                        initial={{ opacity: 0, x: 20 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        transition={{ delay: 0.6 }}
                                        className="bg-white/80 backdrop-blur-sm p-6 rounded-xl shadow-lg border border-gray-200"
                                    >
                                        <h3 className="text-lg font-semibold text-gray-900 mb-4">Severity Distribution</h3>
                                        <ResponsiveContainer width="100%" height={300}>
                                            <PieChart>
                                                <Pie
                                                    data={severityData}
                                                    cx="50%"
                                                    cy="50%"
                                                    labelLine={false}
                                                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                                                    outerRadius={80}
                                                    fill="#8884d8"
                                                    dataKey="value"
                                                >
                                                    {severityData.map((entry, index) => (
                                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                                    ))}
                                                </Pie>
                                                <Tooltip />
                                            </PieChart>
                                        </ResponsiveContainer>
                                    </motion.div>
                                </div>

                                {/* Recent Critical Alerts */}
                                <motion.div
                                    initial={{ opacity: 0, y: 20 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: 0.7 }}
                                    className="bg-white/80 backdrop-blur-sm rounded-xl shadow-lg border border-gray-200"
                                >
                                    <div className="p-6 border-b border-gray-200">
                                        <h3 className="text-lg font-semibold text-gray-900">Recent Critical Alerts</h3>
                                        <p className="text-sm text-gray-600">Latest high-priority threats</p>
                                    </div>
                                    <div className="p-6">
                                        {filteredAlerts.filter(alert => alert.severity === 'critical').slice(0, 5).map((alert, index) => (
                                            <motion.div
                                                key={alert.id}
                                                initial={{ opacity: 0, x: -20 }}
                                                animate={{ opacity: 1, x: 0 }}
                                                transition={{ delay: 0.8 + index * 0.1 }}
                                                className="flex items-center space-x-4 p-4 bg-red-50 rounded-lg mb-3 hover:bg-red-100 transition-colors cursor-pointer"
                                                onClick={() => setSelectedAlert(alert)}
                                            >
                                                {getStatusIcon(alert.severity)}
                                                <div className="flex-1">
                                                    <h4 className="font-medium text-gray-900">{alert.alert_data.title}</h4>
                                                    <p className="text-sm text-gray-600">{alert.alert_data.description}</p>
                                                </div>
                                                <div className="text-right">
                                                    <p className="text-sm font-medium text-red-600">Priority: {alert.priority_score.toFixed(1)}</p>
                                                    <p className="text-xs text-gray-500">{format(new Date(alert.timestamp), 'MMM dd, HH:mm')}</p>
                                                </div>
                                            </motion.div>
                                        ))}
                                    </div>
                                </motion.div>
                            </motion.div>
                        ) : (
                            <motion.div
                                key="alerts"
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -20 }}
                                transition={{ duration: 0.3 }}
                            >
                                {/* Filters and Search */}
                                <div className="bg-white/80 backdrop-blur-sm p-6 rounded-xl shadow-lg border border-gray-200 mb-6">
                                    <div className="flex flex-col md:flex-row gap-4">
                                        <div className="flex-1">
                                            <div className="relative">
                                                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                                                <input
                                                    type="text"
                                                    placeholder="Search alerts..."
                                                    value={searchTerm}
                                                    onChange={(e) => setSearchTerm(e.target.value)}
                                                    className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white/50 backdrop-blur-sm"
                                                />
                                            </div>
                                        </div>

                                        <div className="flex gap-2">
                                            <select
                                                value={filters.severity}
                                                onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
                                                className="px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white/50 backdrop-blur-sm"
                                            >
                                                <option value="">All Severities</option>
                                                <option value="critical">Critical</option>
                                                <option value="high">High</option>
                                                <option value="medium">Medium</option>
                                                <option value="low">Low</option>
                                            </select>

                                            <select
                                                value={filters.source}
                                                onChange={(e) => setFilters({ ...filters, source: e.target.value })}
                                                className="px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white/50 backdrop-blur-sm"
                                            >
                                                <option value="">All Sources</option>
                                                <option value="cisa">CISA</option>
                                                <option value="nvd">NVD</option>
                                                <option value="mitre">MITRE</option>
                                                <option value="virustotal">VirusTotal</option>
                                                <option value="abuseipdb">AbuseIPDB</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>

                                {/* Alerts List */}
                                <div className="bg-white/80 backdrop-blur-sm rounded-xl shadow-lg border border-gray-200">
                                    <div className="p-6 border-b border-gray-200">
                                        <h2 className="text-lg font-semibold text-gray-900">All Alerts</h2>
                                        <p className="text-sm text-gray-600">
                                            {filteredAlerts.length} alerts found
                                        </p>
                                    </div>

                                    {loading ? (
                                        <div className="p-8 text-center">
                                            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
                                            <p className="mt-4 text-gray-600">Loading alerts...</p>
                                        </div>
                                    ) : filteredAlerts.length === 0 ? (
                                        <div className="p-8 text-center">
                                            <Eye className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                                            <p className="text-gray-600">No alerts found matching your criteria</p>
                                        </div>
                                    ) : (
                                        <div className="divide-y divide-gray-200">
                                            {filteredAlerts.map((alert, index) => (
                                                <motion.div
                                                    key={alert.id}
                                                    initial={{ opacity: 0, y: 20 }}
                                                    animate={{ opacity: 1, y: 0 }}
                                                    transition={{ delay: index * 0.05 }}
                                                    className="p-6 hover:bg-gray-50/50 transition-colors cursor-pointer"
                                                    onClick={() => setSelectedAlert(alert)}
                                                >
                                                    <div className="flex justify-between items-start">
                                                        <div className="flex-1">
                                                            <div className="flex items-center space-x-3 mb-2">
                                                                {getStatusIcon(alert.severity)}
                                                                <h3 className="text-lg font-semibold text-gray-900">
                                                                    {alert.alert_data.title}
                                                                </h3>
                                                                <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getSeverityColor(alert.severity)}`}>
                                                                    {alert.severity.toUpperCase()}
                                                                </span>
                                                                <span className={`text-sm font-medium ${getPriorityColor(alert.priority_score)}`}>
                                                                    Priority: {alert.priority_score.toFixed(1)}
                                                                </span>
                                                            </div>

                                                            <p className="text-gray-600 mb-3">
                                                                {alert.alert_data.description}
                                                            </p>

                                                            <div className="flex items-center space-x-4 text-sm text-gray-500">
                                                                <span className="flex items-center space-x-1">
                                                                    <Clock className="h-4 w-4" />
                                                                    <span>{format(new Date(alert.timestamp), 'MMM dd, yyyy HH:mm')}</span>
                                                                </span>
                                                                <span className="flex items-center space-x-1">
                                                                    <Globe className="h-4 w-4" />
                                                                    <span>{alert.source.toUpperCase()}</span>
                                                                </span>
                                                                {alert.alert_data.cve_id && (
                                                                    <span className="flex items-center space-x-1">
                                                                        <Target className="h-4 w-4" />
                                                                        <span>{alert.alert_data.cve_id}</span>
                                                                    </span>
                                                                )}
                                                                {alert.alert_data.cvss_score && (
                                                                    <span className="flex items-center space-x-1">
                                                                        <BarChart3 className="h-4 w-4" />
                                                                        <span>CVSS: {alert.alert_data.cvss_score}</span>
                                                                    </span>
                                                                )}
                                                            </div>

                                                            {alert.tags.length > 0 && (
                                                                <div className="flex flex-wrap gap-2 mt-3">
                                                                    {alert.tags.map((tag, tagIndex) => (
                                                                        <span
                                                                            key={tagIndex}
                                                                            className="px-2 py-1 bg-blue-100 text-blue-700 text-xs rounded-full"
                                                                        >
                                                                            {tag}
                                                                        </span>
                                                                    ))}
                                                                </div>
                                                            )}
                                                        </div>
                                                    </div>
                                                </motion.div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>

                {/* Alert Detail Modal */}
                <AnimatePresence>
                    {selectedAlert && (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
                            onClick={() => setSelectedAlert(null)}
                        >
                            <motion.div
                                initial={{ scale: 0.9, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.9, opacity: 0 }}
                                className="bg-white rounded-xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto"
                                onClick={(e) => e.stopPropagation()}
                            >
                                <div className="p-6 border-b border-gray-200">
                                    <div className="flex justify-between items-start">
                                        <div className="flex items-center space-x-3">
                                            {getStatusIcon(selectedAlert.severity)}
                                            <div>
                                                <h2 className="text-xl font-bold text-gray-900">{selectedAlert.alert_data.title}</h2>
                                                <p className="text-sm text-gray-500">Alert ID: {selectedAlert.id}</p>
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => setSelectedAlert(null)}
                                            className="text-gray-400 hover:text-gray-600"
                                        >
                                            <XCircle className="h-6 w-6" />
                                        </button>
                                    </div>
                                </div>

                                <div className="p-6">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                                        <div>
                                            <h3 className="font-semibold text-gray-900 mb-2">Description</h3>
                                            <p className="text-gray-600">{selectedAlert.alert_data.description}</p>
                                        </div>
                                        <div>
                                            <h3 className="font-semibold text-gray-900 mb-2">Details</h3>
                                            <div className="space-y-2">
                                                <div className="flex justify-between">
                                                    <span className="text-gray-600">Severity:</span>
                                                    <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(selectedAlert.severity)}`}>
                                                        {selectedAlert.severity.toUpperCase()}
                                                    </span>
                                                </div>
                                                <div className="flex justify-between">
                                                    <span className="text-gray-600">Priority Score:</span>
                                                    <span className={`font-medium ${getPriorityColor(selectedAlert.priority_score)}`}>
                                                        {selectedAlert.priority_score.toFixed(1)}
                                                    </span>
                                                </div>
                                                <div className="flex justify-between">
                                                    <span className="text-gray-600">Source:</span>
                                                    <span className="font-medium">{selectedAlert.source.toUpperCase()}</span>
                                                </div>
                                                <div className="flex justify-between">
                                                    <span className="text-gray-600">Status:</span>
                                                    <span className="font-medium">{selectedAlert.status}</span>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    {selectedAlert.alert_data.iocs && selectedAlert.alert_data.iocs.length > 0 && (
                                        <div className="mb-6">
                                            <h3 className="font-semibold text-gray-900 mb-2">Indicators of Compromise (IOCs)</h3>
                                            <div className="bg-gray-50 rounded-lg p-4">
                                                {selectedAlert.alert_data.iocs.map((ioc, index) => (
                                                    <div key={index} className="flex justify-between items-center py-1">
                                                        <span className="text-sm font-medium text-gray-700">{ioc.type.toUpperCase()}:</span>
                                                        <span className="text-sm text-gray-600 font-mono">{ioc.value}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {selectedAlert.tags.length > 0 && (
                                        <div className="mb-6">
                                            <h3 className="font-semibold text-gray-900 mb-2">Tags</h3>
                                            <div className="flex flex-wrap gap-2">
                                                {selectedAlert.tags.map((tag, index) => (
                                                    <span
                                                        key={index}
                                                        className="px-3 py-1 bg-blue-100 text-blue-700 text-sm rounded-full"
                                                    >
                                                        {tag}
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    <div className="text-sm text-gray-500">
                                        <p>Published: {format(new Date(selectedAlert.timestamp), 'PPP p')}</p>
                                        <p>Last Updated: {format(new Date(selectedAlert.timestamp), 'PPP p')}</p>
                                    </div>
                                </div>
                            </motion.div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </main>
        </>
    )
}
