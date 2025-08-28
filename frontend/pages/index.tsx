import { useState, useEffect } from 'react'
import Head from 'next/head'
import { 
  Shield, 
  AlertTriangle, 
  TrendingUp, 
  Search, 
  Filter,
  Clock,
  Zap,
  Eye,
  BarChart3,
  RefreshCw
} from 'lucide-react'

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
    }
  }

  const triggerCollection = async () => {
    setRefreshing(true)
    try {
      const response = await fetch('/api/collect', { method: 'POST' })
      const data = await response.json()
      
      // Refresh all data
      await Promise.all([
        fetchDashboardData(),
        fetchAlerts(),
        fetchStatistics()
      ])
      
      alert(`Collection completed: ${data.alerts_processed} new alerts processed`)
    } catch (error) {
      console.error('Error triggering collection:', error)
      alert('Error triggering collection')
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

  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch = searchTerm === '' || 
      alert.alert_data.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.alert_data.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.alert_data.source.toLowerCase().includes(searchTerm.toLowerCase())
    
    const matchesSeverity = filters.severity === '' || alert.severity === filters.severity
    const matchesSource = filters.source === '' || alert.source === filters.source
    
    return matchesSearch && matchesSeverity && matchesSource
  })

  return (
    <>
      <Head>
        <title>C4A Alerts - Threat Intelligence Dashboard</title>
        <meta name="description" content="Real-time threat intelligence and monitoring platform" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      
      <main className="min-h-screen bg-gray-50">
        {/* Header */}
        <header className="bg-white shadow-sm border-b">
          <div className="container mx-auto px-4 py-4">
            <div className="flex justify-between items-center">
              <div className="flex items-center space-x-3">
                <Shield className="h-8 w-8 text-blue-600" />
                <h1 className="text-2xl font-bold text-gray-900">
                  C4A Alerts
                </h1>
                <span className="text-sm text-gray-500">Threat Intelligence Dashboard</span>
              </div>
              
              <button
                onClick={triggerCollection}
                disabled={refreshing}
                className="flex items-center space-x-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white px-4 py-2 rounded-lg font-medium transition-colors"
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
        </header>

        <div className="container mx-auto px-4 py-8">
          {/* Dashboard Stats */}
          {dashboardData && (
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Recent Alerts</p>
                    <p className="text-2xl font-bold text-gray-900">{dashboardData.recent_alerts}</p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-blue-600" />
                </div>
                <p className="text-xs text-gray-500 mt-2">Last 24 hours</p>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Critical</p>
                    <p className="text-2xl font-bold text-red-600">{dashboardData.critical_alerts}</p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-red-600" />
                </div>
                <p className="text-xs text-gray-500 mt-2">High priority</p>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">High Severity</p>
                    <p className="text-2xl font-bold text-orange-600">{dashboardData.high_alerts}</p>
                  </div>
                  <TrendingUp className="h-8 w-8 text-orange-600" />
                </div>
                <p className="text-xs text-gray-500 mt-2">Requires attention</p>
              </div>

              <div className="bg-white p-6 rounded-lg shadow-sm border">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Top Source</p>
                    <p className="text-lg font-bold text-gray-900">
                      {dashboardData.top_sources[0]?.[0]?.toUpperCase() || 'N/A'}
                    </p>
                  </div>
                  <BarChart3 className="h-8 w-8 text-green-600" />
                </div>
                <p className="text-xs text-gray-500 mt-2">
                  {dashboardData.top_sources[0]?.[1] || 0} alerts
                </p>
              </div>
            </div>
          )}

          {/* Filters and Search */}
          <div className="bg-white p-6 rounded-lg shadow-sm border mb-6">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search alerts..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </div>

              <div className="flex gap-2">
                <select
                  value={filters.severity}
                  onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
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
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
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
          <div className="bg-white rounded-lg shadow-sm border">
            <div className="p-6 border-b">
              <h2 className="text-lg font-semibold text-gray-900">Recent Alerts</h2>
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
                {filteredAlerts.map((alert) => (
                  <div key={alert.id} className="p-6 hover:bg-gray-50 transition-colors">
                    <div className="flex justify-between items-start">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          <h3 className="text-lg font-semibold text-gray-900">
                            {alert.alert_data.title}
                          </h3>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(alert.severity)}`}>
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
                            <span>{new Date(alert.timestamp).toLocaleString()}</span>
                          </span>
                          <span>Source: {alert.source.toUpperCase()}</span>
                          {alert.alert_data.cve_id && (
                            <span>CVE: {alert.alert_data.cve_id}</span>
                          )}
                          {alert.alert_data.cvss_score && (
                            <span>CVSS: {alert.alert_data.cvss_score}</span>
                          )}
                        </div>
                        
                        {alert.tags.length > 0 && (
                          <div className="flex flex-wrap gap-2 mt-3">
                            {alert.tags.map((tag, index) => (
                              <span
                                key={index}
                                className="px-2 py-1 bg-gray-100 text-gray-700 text-xs rounded-full"
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Statistics */}
          {statistics && (
            <div className="mt-8 bg-white p-6 rounded-lg shadow-sm border">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Statistics</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center">
                  <p className="text-2xl font-bold text-gray-900">{statistics.total_alerts}</p>
                  <p className="text-sm text-gray-600">Total Alerts</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold text-blue-600">{statistics.monthly_alerts}</p>
                  <p className="text-sm text-gray-600">This Month</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold text-red-600">{statistics.severity_distribution.critical}</p>
                  <p className="text-sm text-gray-600">Critical</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold text-orange-600">{statistics.severity_distribution.high}</p>
                  <p className="text-sm text-gray-600">High</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </>
  )
}
