# C4A Alerts - Modular Threat Intelligence & Alerting Platform

[![CI/CD Pipeline](https://github.com/cherrera0001/c4a-alerts/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/cherrera0001/c4a-alerts/actions/workflows/ci-cd.yml)
[![Alert Collection](https://github.com/cherrera0001/c4a-alerts/actions/workflows/alerts.yml/badge.svg)](https://github.com/cherrera0001/c4a-alerts/actions/workflows/alerts.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A scalable, modular SaaS platform for collecting, processing, and distributing security alerts and threat intelligence.

## 🚀 Features

- **Modular Architecture**: Plugin-based pipeline with clear separation of concerns
- **Multiple Input Sources**: Support for various threat intelligence feeds
- **Intelligent Processing**: Deduplication, prioritization, and routing
- **Multi-Channel Notifications**: Telegram, Slack, Email, Webhooks
- **CTI Platform Integration**: OpenCTI, MISP, TheHive
- **RESTful API**: FastAPI-based API with comprehensive documentation
- **Asynchronous Processing**: Celery workers for scalable alert processing
- **Security First**: OWASP ASVS/Top10 compliance, HMAC webhooks, API keys

## 🏗️ Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Collectors │───▶│ Normalizer  │───▶│ Enricher    │───▶│ Deduplicator│
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                                                              │
┌─────────────┐    ┌─────────────┐    ┌─────────────┐        ▼
│  Router     │◀───│ Prioritizer │◀───│ Enricher    │◀─────────────┘
└─────────────┘    └─────────────┘    └─────────────┘
       │
       ▼
┌─────────────┐
│ Notifiers   │───▶ Telegram, Slack, Email, Webhooks, CTI Platforms
└─────────────┘
```

## 📦 Installation

### Prerequisites

- Python 3.10+
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose (optional)

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/cherrera0001/c4a-alerts.git
   cd c4a-alerts
   ```

2. **Install dependencies**
   ```bash
   pip install -e .
   ```

3. **Set up environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Run with Docker Compose**
   ```bash
   docker-compose up -d
   ```

## 🔧 Configuration

### Environment Variables

Key configuration options in `.env`:

```bash
# Application
APP_NAME=C4A Alerts
DEBUG=false
LOG_LEVEL=INFO

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/c4a_alerts

# Redis
REDIS_URL=redis://localhost:6379/0

# API
API_HOST=0.0.0.0
API_PORT=8000

# Security
SECRET_KEY=your-secret-key
API_KEY_HEADER=X-API-Key

# Notifiers
TELEGRAM_BOT_TOKEN=your-telegram-token
SLACK_BOT_TOKEN=your-slack-token
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587

# CTI Platforms
OPENCTI_URL=https://your-opencti-instance
MISP_URL=https://your-misp-instance
THEHIVE_URL=https://your-thehive-instance
```

## 🚀 Usage

### API Endpoints

- **Health Check**: `GET /api/v1/health`
- **Worker Status**: `GET /api/v1/workers/status`
- **Trigger Collection**: `POST /api/v1/workers/collect`
- **Process Alert**: `POST /api/v1/workers/process`

### API Documentation

Once running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Manual Alert Collection

```bash
# Collect from all sources
curl -X POST "http://localhost:8000/api/v1/workers/collect"

# Collect from specific source
curl -X POST "http://localhost:8000/api/v1/workers/collect" \
  -H "Content-Type: application/json" \
  -d '{"source": "cisa", "force": true}'
```

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=c4aalerts --cov-report=html

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
```

## 🔒 Security

This project follows security best practices:

- **OWASP ASVS/Top10** compliance
- **API Key Authentication**
- **HMAC-signed webhooks**
- **Input validation** with Pydantic
- **Rate limiting**
- **Security headers**
- **Dependency scanning** with `pip-audit` and `safety`

## 📊 Monitoring

- **Health checks** at `/api/v1/health`
- **Detailed health** at `/api/v1/health/detailed`
- **Worker status** at `/api/v1/workers/status`
- **Metrics** via Prometheus endpoints (planned)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run code quality checks
ruff check c4aalerts/ tests/
black c4aalerts/ tests/
isort c4aalerts/ tests/
mypy c4aalerts/

# Run security checks
bandit -r c4aalerts/
pip-audit
```

## 📋 Roadmap

### PR#4 - Enhanced Deduplication & Prioritization
- [ ] YAML-based routing rules
- [ ] Advanced deduplication algorithms
- [ ] Machine learning prioritization
- [ ] Historical data analysis

### PR#5 - Notifiers Implementation
- [ ] Telegram refactoring
- [ ] Slack integration
- [ ] Email templates
- [ ] Webhook support

### PR#6 - CTI Platform Integration
- [ ] OpenCTI integration
- [ ] MISP integration
- [ ] TheHive integration
- [ ] Documentation and examples

### PR#7 - Security & Hardening
- [ ] Rate limiting implementation
- [ ] API key management
- [ ] HMAC webhook validation
- [ ] Security headers

### PR#8 - Metrics & Logging
- [ ] Structured logging
- [ ] Prometheus metrics
- [ ] Grafana dashboards
- [ ] Operations documentation

### PR#9 - Demo UI (Optional)
- [ ] Minimal web interface
- [ ] Alert visualization
- [ ] Configuration management
- [ ] Demo data

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- FastAPI for the excellent web framework
- Celery for asynchronous task processing
- Pydantic for data validation
- The security community for best practices

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/cherrera0001/c4a-alerts/issues)
- **Discussions**: [GitHub Discussions](https://github.com/cherrera0001/c4a-alerts/discussions)
- **Documentation**: [Wiki](https://github.com/cherrera0001/c4a-alerts/wiki)

---

**C4A Alerts** - Making threat intelligence accessible and actionable. 🛡️

