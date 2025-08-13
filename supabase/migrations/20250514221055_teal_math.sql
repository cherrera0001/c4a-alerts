-- Esquema de base de datos mejorado para C4A Alerts
-- Soporte para embeddings, scoring avanzado y threat intelligence

-- Tabla principal de alertas
CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity_score REAL DEFAULT 0.0,
    cvss_score REAL,
    epss_score REAL,
    threat_score REAL,
    priority TEXT CHECK (priority IN ('critical', 'high', 'medium', 'low', 'info')),
    status TEXT CHECK (status IN ('pending', 'processing', 'completed', 'failed')) DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    processed_at DATETIME,
    raw_data TEXT, -- JSON serializado
    metadata TEXT, -- JSON con metadatos adicionales
    hash_signature TEXT UNIQUE, -- Para deduplicación
    FOREIGN KEY (source_id) REFERENCES sources (id)
);

-- Índices para alertas
CREATE INDEX idx_alerts_severity ON alerts(severity_score DESC);
CREATE INDEX idx_alerts_priority ON alerts(priority);
CREATE INDEX idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX idx_alerts_source ON alerts(source_id);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_hash ON alerts(hash_signature);

-- Tabla de fuentes de datos
CREATE TABLE sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL CHECK (type IN ('rss', 'api', 'webhook', 'file')),
    url TEXT,
    config TEXT, -- JSON con configuración específica de la fuente
    enabled BOOLEAN DEFAULT TRUE,
    last_fetch DATETIME,
    fetch_interval INTEGER DEFAULT 3600, -- segundos
    error_count INTEGER DEFAULT 0,
    last_error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de CVEs
CREATE TABLE cves (
    id TEXT PRIMARY KEY, -- CVE-YYYY-NNNN
    description TEXT,
    cvss_v3_score REAL,
    cvss_v3_vector TEXT,
    cwe_id TEXT,
    published_date DATETIME,
    last_modified DATETIME,
    severity TEXT CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    exploitability_score REAL,
    impact_score REAL,
    epss_score REAL,
    epss_percentile REAL,
    kev_catalog BOOLEAN DEFAULT FALSE, -- CISA Known Exploited Vulnerabilities
    references TEXT, -- JSON array de referencias
    affected_products TEXT, -- JSON array de productos afectados
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Índices para CVEs
CREATE INDEX idx_cves_score ON cves(cvss_v3_score DESC);
CREATE INDEX idx_cves_severity ON cves(severity);
CREATE INDEX idx_cves_published ON cves(published_date DESC);
CREATE INDEX idx_cves_epss ON cves(epss_score DESC);
CREATE INDEX idx_cves_kev ON cves(kev_catalog);

-- Tabla de relación entre alertas y CVEs
CREATE TABLE alert_cves (
    alert_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    relevance_score REAL DEFAULT 1.0, -- Qué tan relevante es este CVE para esta alerta
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (alert_id, cve_id),
    FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE,
    FOREIGN KEY (cve_id) REFERENCES cves (id) ON DELETE CASCADE
);

-- Tabla de embeddings para ML
CREATE TABLE alert_embeddings (
    alert_id TEXT PRIMARY KEY,
    model_name TEXT NOT NULL, -- nombre del modelo usado para generar embedding
    model_version TEXT NOT NULL,
    embedding BLOB NOT NULL, -- vector serializado (numpy array)
    dimensions INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE
);

-- Tabla de clusters de alertas similares
CREATE TABLE alert_clusters (
    id TEXT PRIMARY KEY,
    name TEXT,
    centroid BLOB, -- embedding del centroide
    model_name TEXT NOT NULL,
    cluster_algorithm TEXT NOT NULL, -- k-means, dbscan, etc.
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Relación muchos a muchos entre alertas y clusters
CREATE TABLE alert_cluster_membership (
    alert_id TEXT NOT NULL,
    cluster_id TEXT NOT NULL,
    distance REAL, -- distancia al centroide
    confidence REAL, -- confianza en la asignación
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (alert_id, cluster_id),
    FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE,
    FOREIGN KEY (cluster_id) REFERENCES alert_clusters (id) ON DELETE CASCADE
);

-- Tabla de indicadores de compromiso (IoCs)
CREATE TABLE indicators (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL CHECK (type IN ('ip', 'domain', 'url', 'hash', 'email', 'file')),
    value TEXT NOT NULL,
    confidence REAL DEFAULT 0.5 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    tags TEXT, -- JSON array de tags
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    times_seen INTEGER DEFAULT 1,
    malicious_confidence REAL DEFAULT 0.0,
    context TEXT, -- JSON con contexto adicional
    UNIQUE(type, value)
);

-- Índices para indicadores
CREATE INDEX idx_indicators_type ON indicators(type);
CREATE INDEX idx_indicators_value ON indicators(value);
CREATE INDEX idx_indicators_confidence ON indicators(confidence DESC);
CREATE INDEX idx_indicators_malicious ON indicators(malicious_confidence DESC);

-- Relación entre alertas e indicadores
CREATE TABLE alert_indicators (
    alert_id TEXT NOT NULL,
    indicator_id TEXT NOT NULL,
    context TEXT, -- contexto específico de esta relación
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (alert_id, indicator_id),
    FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE,
    FOREIGN KEY (indicator_id) REFERENCES indicators (id) ON DELETE CASCADE
);

-- Tabla de campañas de amenazas
CREATE TABLE threat_campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    threat_actor TEXT,
    tactics TEXT, -- JSON array de tácticas MITRE ATT&CK
    techniques TEXT, -- JSON array de técnicas MITRE ATT&CK
    first_observed DATETIME,
    last_observed DATETIME,
    confidence REAL DEFAULT 0.5,
    severity TEXT CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status TEXT CHECK (status IN ('active', 'dormant', 'ended')) DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Relación entre alertas y campañas
CREATE TABLE alert_campaigns (
    alert_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    attribution_confidence REAL DEFAULT 0.5,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (alert_id, campaign_id),
    FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE,
    FOREIGN KEY (campaign_id) REFERENCES threat_campaigns (id) ON DELETE CASCADE
);

-- Tabla de notificaciones enviadas
CREATE TABLE notifications (
    id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('telegram', 'email', 'slack', 'webhook')),
    recipient TEXT NOT NULL,
    status TEXT CHECK (status IN ('pending', 'sent', 'failed')) DEFAULT 'pending',
    attempts INTEGER DEFAULT 0,
    last_attempt DATETIME,
    error_message TEXT,
    sent_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE
);

-- Tabla de configuración del sistema
CREATE TABLE system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insertar configuración inicial
INSERT OR IGNORE INTO system_config (key, value, description) VALUES
('version', '2.0.0', 'Versión del esquema de base de datos'),
('embedding_model', 'sentence-transformers/all-MiniLM-L6-v2', 'Modelo para generar embeddings'),
('clustering_algorithm', 'kmeans', 'Algoritmo de clustering por defecto'),
('max_alerts_per_run', '1000', 'Máximo número de alertas a procesar por ejecución'),
('notification_retry_limit', '3', 'Límite de reintentos para notificaciones'),
('duplicate_threshold_hours', '24', 'Horas para considerar una alerta como duplicada');

-- Views útiles
CREATE VIEW active_alerts AS
SELECT 
    a.*,
    s.name as source_name,
    COUNT(ac.cve_id) as cve_count,
    COUNT(ai.indicator_id) as indicator_count
FROM alerts a
JOIN sources s ON a.source_id = s.id
LEFT JOIN alert_cves ac ON a.id = ac.alert_id
LEFT JOIN alert_indicators ai ON a.id = ai.alert_id
WHERE a.status != 'failed'
GROUP BY a.id;

CREATE VIEW high_priority_alerts AS
SELECT * FROM active_alerts 
WHERE priority IN ('critical', 'high') 
ORDER BY created_at DESC;

CREATE VIEW threat_overview AS
SELECT 
    DATE(created_at) as date,
    priority,
    COUNT(*) as alert_count,
    AVG(threat_score) as avg_threat_score
FROM alerts 
WHERE created_at >= datetime('now', '-30 days')
GROUP BY DATE(created_at), priority
ORDER BY date DESC, alert_count DESC;
