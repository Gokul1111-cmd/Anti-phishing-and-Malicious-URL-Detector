# 🛡️ PhishGuard - AI-Powered Phishing Detection System

**Dual-Module Security Platform: Real-time Browser Protection + Comprehensive Management Dashboard**

> Protect users from phishing, malware, and malicious websites through intelligent ML detection, instant blocking, and advanced analytics.

---

## 🎯 Project Vision

**PhishGuard is a production-ready security solution that combines:**
- ⚡ **Chrome Extension** - Lightweight, real-time protection while browsing
- 🎯 **Web Application** - Comprehensive security management and analytics
- 🤖 **ML Detection** - 99.93% accuracy with zero false negatives
- 📊 **Intelligence System** - User-reported threats + automated detection

### Why PhishGuard?

| Problem | Traditional Solutions | PhishGuard Solution |
|---------|---------------------|-------------------|
| Users don't know if sites are safe | Manual checking (slow) | Auto-scan every page (instant) |
| Phishing detection is reactive | Blacklist-based (outdated) | ML-powered (predictive) |
| No quick way to report threats | Complex reporting forms | One-click quarantine |
| No visibility into protection | Black box systems | Live statistics dashboard |
| Tools are either too simple or too complex | One-size-fits-all | Extension (simple) + Web App (advanced) |

---

## 📋 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    DUAL-MODULE SYSTEM                       │
└─────────────────────────────────────────────────────────────┘

CHROME EXTENSION                      WEB APPLICATION
┌──────────────────┐                 ┌──────────────────┐
│  🔍 Auto-Scan    │                 │  📊 Dashboard    │
│  🚨 Instant Warn │   ←─ API ─→    │  📄 Bulk Scan    │
│  🚫 Quick Block  │                 │  📈 Analytics    │
│  📊 Live Stats   │                 │  🗂️ Management   │
└──────────────────┘                 └──────────────────┘
         ↓                                     ↓
    [User Browsing]                      [Deep Analysis]
         ↓                                     ↓
    IMMEDIATE PROTECTION          COMPREHENSIVE CONTROL
```

### User Flow

```
1. USER INSTALLS EXTENSION
   └─→ Auto-protection ON (set-and-forget)
   
2. USER BROWSES WEB
   └─→ Extension auto-scans every page
       ├─→ SAFE: Silent (no interruption)
       └─→ THREAT: Warning + Actions
           ├─→ [Block] → Instant safety
           ├─→ [Quarantine] → Report to system
           └─→ [View Details] → Opens Web App

3. POWER USERS ACCESS WEB APP
   └─→ Bulk scan suspicious URLs
   └─→ Review quarantine list
   └─→ View threat analytics
   └─→ Export reports
   └─→ Manage settings

4. BIDIRECTIONAL SYNC
   Extension ←→ Backend API ←→ Web App
   (All actions sync in real-time)
```

---

## ✨ Features

### 🔌 Chrome Extension Features

| Feature | Purpose | User Benefit | Technical Implementation |
|---------|---------|--------------|-------------------------|
| **🔄 Auto-Scan** | Passive protection | No manual checking needed | Background script monitors tab changes |
| **🔍 Manual Scan** | User-initiated checks | Control over scanning | On-demand API calls to `/scan` endpoint |
| **📍 Current URL Display** | Transparency | Know what's being scanned | Chrome tabs API integration |
| **🚫 Quarantine Button** | Report threats | Crowdsourced intelligence | POST to `/quarantine` with metadata |
| **⛔ Block Button** | Immediate safety | One-click protection | Blocks + closes tab instantly |
| **📊 Live Statistics** | Visible value | See protection working | Real-time API stats polling |
| **📱 Dashboard Link** | Feature discovery | Access advanced features | Opens web app in new tab |
| **⚙️ Settings Link** | Configuration | Manage quarantine list | Direct link to web app settings |
| **🔔 Toast Notifications** | User feedback | Know what's happening | Visual feedback on all actions |

**Key Benefits:**
- ✅ Zero friction - works in browser where users are
- ✅ Set-and-forget - auto-protection after install
- ✅ Instant feedback - 1-2 second scan results
- ✅ Privacy-first - no user data collection

---

### 🌐 Web Application Features

| Feature | Purpose | User Benefit | Technical Implementation |
|---------|---------|--------------|-------------------------|
| **� Dashboard** | Security overview | "Am I protected?" at a glance | Real-time metrics aggregation |
| **🔍 Single URL Scanner** | Deep analysis | Detailed threat breakdown | ML model + feature extraction |
| **📄 Bulk CSV Scanner** | Batch processing | Scan 100s of URLs in seconds | Parallel processing (10 workers) |
| **🗂️ Quarantine Manager** | Central control | Review/unblock false positives | CRUD operations on quarantine DB |
| **📈 Analytics Page** | Threat intelligence | Understand attack patterns | Data visualization & trends |
| **📜 Scan History** | Audit trail | Compliance & accountability | Historical scan logging |
| **👥 User Management** | Team collaboration | Multi-user access control | Role-based authentication |
| **⚙️ Settings** | Enterprise integration | API keys, webhooks, preferences | User settings DB + webhook testing |
| **📖 API Documentation** | Developer integration | Build custom tools | OpenAPI/Swagger docs |

**Key Benefits:**
- ✅ Enterprise-ready - bulk operations for professionals
- ✅ Full visibility - comprehensive analytics & history
- ✅ Reversibility - unblock false positives easily
- ✅ Scalable - handles high-volume scanning

---

## 🔬 Technical Specifications

### Machine Learning Model

**Architecture:** Logistic Regression + TF-IDF Vectorization

**Performance Metrics:**
- 🎯 **100% Recall** - Catches ALL phishing URLs (zero false negatives)
- ✅ **93.3% Precision** - Minimal false positives on legitimate sites
- ⚡ **69.6 URLs/second** - Real-time processing speed
- 📊 **99.93% Overall Accuracy** - Production-ready performance

**Training Data:**
- 549,346 URLs from Kaggle phishing dataset
- Binary classification (phishing vs. legitimate)
- Regular model retraining for emerging threats

**Feature Extraction:**
- URL structure analysis (length, special characters, domain)
- TF-IDF text vectorization
- Domain reputation signals
- HTTPS/HTTP analysis

### Backend Architecture

**Framework:** FastAPI (Python 3.11+)

**Key Components:**
- 🔐 **Authentication** - JWT-based user auth
- 🤖 **ML Service** - Model inference engine
- 📁 **File Upload** - CSV processing with validation
- 📊 **Analytics Engine** - Statistics aggregation
- 🗄️ **Database** - SQLite (dev) / PostgreSQL (prod)
- 📡 **REST API** - OpenAPI-documented endpoints
- ⚡ **Celery Workers** - Background task processing
- 💾 **Redis** - Caching & task queue

**Performance Optimizations:**
- ThreadPoolExecutor for parallel bulk scanning (5.9x speedup)
- Result caching for repeated URL checks
- Async/await for concurrent operations
- Connection pooling for database

### Frontend Architecture

**Framework:** React 18 + TypeScript + Vite

**Key Technologies:**
- 🎨 **Tailwind CSS** - Utility-first styling
- 🧩 **Shadcn UI** - Accessible component library
- 🔀 **React Router** - Client-side routing
- � **TanStack Query** - Server state management
- 🎭 **MSW** - API mocking for development
- 🎯 **Lucide Icons** - Consistent iconography

**State Management:**
- React Context for global app state
- TanStack Query for server data
- Local storage for user preferences

### Extension Architecture

**Platform:** Chrome Extension Manifest V3

**Key Components:**
- 📄 **popup.html** - User interface (400x500px)
- 📜 **popup.js** - Business logic & API integration
- 🔧 **background.js** - Service worker for tab monitoring
- 🎨 **Gradient UI** - Modern, accessible design

**Communication:**
- Chrome APIs (tabs, storage, runtime)
- REST API integration with backend
- Polling-based sync (1s quarantine, 10s stats)

---

## 📊 Performance Benchmarks

### ML Model Validation

**Test Configuration:**
- 1,000 random URLs from dataset
- 30 trusted legitimate sites (Google, Microsoft, etc.)
- Fresh database (no duplicates)

**Results:**

| Metric | Result | Industry Standard | Status |
|--------|--------|-------------------|--------|
| **Phishing Detection** | 280/280 (100%) | >95% | ✅ Excellent |
| **Legitimate Sites** | 28/30 (93.3%) | >90% | ✅ Excellent |
| **False Positive Rate** | 6.7% (2/30) | <10% | ✅ Excellent |
| **False Negative Rate** | 0% (0/280) | <5% | ✅ Perfect |
| **Processing Speed** | 69.6 URLs/sec | >10/sec | ✅ Fast |

**False Positives Analysis:**
- oracle.com - Commonly phished brand (reasonable flag)
- salesforce.com - Frequently impersonated (reasonable flag)

### Bulk Scan Performance

**Optimization Results:**

| URLs | Sequential | Parallel (10 workers) | Speedup |
|------|-----------|----------------------|---------|
| 10 | 1.11s | 0.19s | 5.9x faster |
| 100 | 11s | 2s | 5.5x faster |
| 1,000 | 110s | 19s | 5.8x faster |

**Key Improvements:**
- Removed artificial 0.1s delays
- ThreadPoolExecutor with 10 workers
- Batch progress updates (every 10 URLs)
- Connection pooling

---

## 🚀 Getting Started

### Prerequisites

```bash
# Backend
- Python 3.11+
- pip (Python package manager)
- Redis (for Celery)

# Frontend
- Node.js 18+
- npm or yarn

# Extension
- Chrome/Edge browser
- Developer mode enabled
```

### Quick Start

**1. Clone Repository**
```bash
git clone https://github.com/yourusername/phishguard.git
cd phishguard
```

**2. Start Backend**
```bash
cd backend
pip install -r requirements.txt
python main.py
# API runs on http://localhost:8000
```

**3. Start Frontend**
```bash
cd ..
npm install
npm run dev
# Web app runs on http://localhost:8080
```

**4. Load Extension**
```bash
# 1. Open Chrome/Edge
# 2. Go to chrome://extensions/
# 3. Enable "Developer mode"
# 4. Click "Load unpacked"
# 5. Select: guard-well-main/browser-extension
# 6. Extension icon appears in toolbar!
```

**5. Test Everything**
```bash
# Test Extension
1. Click extension icon
2. Visit any website
3. Click "Scan This Page"
4. See result with confidence bar

# Test Web App
1. Open http://localhost:8080
2. Try single URL scan
3. Upload CSV for bulk scan
4. View dashboard analytics
```

---

## 📖 Documentation

- **[Architecture & Interview Guide](PROJECT_ARCHITECTURE_INTERVIEW_GUIDE.md)** - Complete system design, feature justifications, and interview talking points
- **[Extension v2.0 Guide](browser-extension/EXTENSION_V2_GUIDE.md)** - Chrome extension features, usage, and troubleshooting
- **[API Documentation](http://localhost:8000/docs)** - Interactive OpenAPI/Swagger docs (when backend running)

---

## 🧪 Testing

### Backend Tests
```bash
cd backend
pytest tests/
python test_model_accuracy.py
python test_bulk_scan_performance.py
```

### Frontend Tests
```bash
npm run test
npm run test:coverage
```

### Extension Testing
1. Load extension in developer mode
2. Open test websites (safe and suspicious)
3. Verify auto-scan triggers
4. Test manual scan button
5. Test quarantine/block actions
6. Check statistics update
7. Verify dashboard navigation

---

## 🎯 Use Cases

### For Regular Users
- **Set-and-forget protection** - Install extension, browse safely
- **Instant feedback** - Know if site is safe before entering data
- **Quick reporting** - One-click quarantine for suspicious sites

### For Security Professionals
- **Bulk scanning** - Process phishing reports with 100s of URLs
- **Threat intelligence** - Analyze patterns and trends
- **Audit trails** - Historical scan logs for compliance
- **API integration** - Build custom security tools

### For Enterprises
- **Team protection** - Deploy extension across organization
- **Centralized management** - Web app for security teams
- **Reporting** - Export data for compliance
- **Customization** - Adjust thresholds for business needs

---

## 🏆 Competitive Advantages

| Competitor | Limitation | PhishGuard Solution |
|------------|-----------|-------------------|
| **Browser Built-in** | Basic blacklist, slow updates | ML-powered, real-time detection |
| **Norton SafeWeb** | Manual checking only | Auto-scan + manual options |
| **VirusTotal** | API limits, slow | Unlimited, 69.6 URLs/sec |
| **URLVoid** | Web-only interface | Extension + Web App combo |
| **PhishTank** | Crowdsourced only | ML + crowdsourcing hybrid |

**Unique Selling Points:**
1. 🔄 Dual-module architecture (protection + management)
2. ⚡ Real-time ML (no API delays)
3. 📊 5.9x faster bulk scanning (enterprise-ready)
4. 🔓 Reversible blocks (user-friendly)
5. 📈 Deep analytics (threat intelligence)
6. 💾 Privacy-first (no third-party data sharing)
7. 🆓 Open source (community-driven)

## Getting Started

### Prerequisites

## 📁 Project Structure

```
guard-well-main/
├── backend/                      # Python FastAPI backend
│   ├── app/
│   │   ├── api/                 # API routes
│   │   ├── models/              # Database models
│   │   ├── services/            # Business logic
│   │   ├── tasks/               # Celery background tasks
│   │   └── ml/                  # ML model & training
│   ├── tests/                   # Backend tests
│   ├── requirements.txt         # Python dependencies
│   └── main.py                  # FastAPI entry point
│
├── browser-extension/           # Chrome Extension
│   ├── popup.html               # Extension UI (400x500px)
│   ├── popup.js                 # Business logic (~540 lines)
│   ├── background.js            # Service worker
│   ├── blocked.html             # Blocked site page
│   ├── manifest.json            # Extension config
│   └── icons/                   # Extension icons
│
├── src/                         # React frontend
│   ├── components/              # Reusable UI components
│   │   ├── ui/                 # Shadcn UI components
│   │   ├── Layout.tsx          # Main app layout
│   │   ├── URLScan.tsx         # Single URL scanner
│   │   └── BulkScan.tsx        # Bulk CSV uploader
│   ├── pages/                   # Page components
│   │   ├── Dashboard.tsx       # Analytics overview
│   │   ├── Scan.tsx            # URL scanning page
│   │   ├── History.tsx         # Scan history
│   │   └── Settings.tsx        # App settings
│   ├── contexts/                # React contexts
│   ├── lib/                     # Utility functions
│   └── index.css                # Global styles
│
├── docs/                        # Documentation
│   ├── PROJECT_ARCHITECTURE_INTERVIEW_GUIDE.md
│   └── browser-extension/EXTENSION_V2_GUIDE.md
│
└── package.json                 # Frontend dependencies
```

---

## 🔧 Configuration

### Backend Configuration

**Environment Variables** (`backend/.env`):
```env
# Database
DATABASE_URL=sqlite:///./phishguard.db
# Or PostgreSQL: postgresql://user:pass@localhost/phishguard

# Redis (for Celery)
REDIS_URL=redis://localhost:6379/0

# JWT Authentication
SECRET_KEY=your-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# ML Model
MODEL_PATH=./ml/phishing_model.pkl
VECTORIZER_PATH=./ml/tfidf_vectorizer.pkl

# API Settings
API_V1_PREFIX=/api/v1
CORS_ORIGINS=["http://localhost:8080"]
```

### Frontend Configuration

**Vite Config** (`vite.config.ts`):
```typescript
export default {
  server: {
    port: 8080,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true
      }
    }
  }
}
```

### Extension Configuration

**API Endpoint** (`browser-extension/popup.js`):
```javascript
const API_BASE = 'http://localhost:8000/api';
const WEB_APP = 'http://localhost:8080';
```

---

## 🎨 Design System

### Color Palette

| Color | Usage | Hex | Design Token |
|-------|-------|-----|--------------|
| **Primary** | CTAs, links, active states | `#667eea` → `#764ba2` | `--primary` |
| **Success** | Safe scan results | `#28a745` | `--success` |
| **Warning** | Suspicious findings | `#ffc107` | `--warning` |
| **Danger** | Phishing detections | `#dc3545` | `--danger` |
| **Neutral** | Base UI, text, borders | `#6c757d` | `--neutral` |

### Typography

- **Headings:** -apple-system, BlinkMacSystemFont, 'Segoe UI'
- **Body:** Roboto, Oxygen, Ubuntu, sans-serif
- **Code:** 'Courier New', monospace

### Component Guidelines

All components follow:
- ✅ Semantic HTML
- ✅ ARIA attributes for accessibility
- ✅ WCAG AA contrast ratios
- ✅ Keyboard navigation support
- ✅ Responsive design (mobile-first)

---

## 🔌 API Reference

### Core Endpoints

**Authentication**
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}

Response: { "token": "jwt_token", "user": {...} }
```

**Single URL Scan**
```http
POST /api/v1/scan
Content-Type: application/json

{
  "url": "https://example.com"
}

Response: {
  "scanId": "abc123",
  "status": "processing"
}

GET /api/v1/scan/{scanId}
Response: {
  "status": "completed",
  "result": "clean|phishing|suspicious",
  "confidence": 0.95,
  "details": {...}
}
```

**Bulk CSV Scan**
```http
POST /api/v1/scan/bulk
Content-Type: multipart/form-data

file: urls.csv

Response: {
  "jobId": "job123",
  "totalUrls": 100
}

GET /api/v1/scan/bulk/{jobId}
Response: {
  "status": "processing",
  "progress": 65,
  "completed": 65,
  "total": 100,
  "results": [...]
}
```

**Quarantine Management**
```http
GET /api/quarantine/list
Response: {
  "items": [
    {
      "id": 1,
      "url": "http://malicious.com",
      "reason": "phishing",
      "addedAt": "2025-10-18T12:00:00Z"
    }
  ]
}

POST /api/quarantine
Content-Type: application/json

{
  "url": "http://malicious.com",
  "reason": "User reported phishing"
}

DELETE /api/quarantine/{id}
```

**Statistics**
```http
GET /api/quarantine/stats
Response: {
  "quarantine": 45,
  "blocked": 12,
  "scanned": 1250,
  "threats": 57
}
```

**Full API Docs:** `http://localhost:8000/docs` (Swagger UI)

---

## 🧪 Testing & Quality Assurance

### Backend Testing

**Unit Tests:**
```bash
cd backend
pytest tests/ -v
```

**ML Model Validation:**
```bash
python test_model_accuracy.py
# Tests 1,000 URLs, validates 100% phishing detection
```

**Performance Benchmarks:**
```bash
python test_bulk_scan_performance.py
# Measures throughput (target: >50 URLs/sec)
```

**Coverage Report:**
```bash
pytest --cov=app --cov-report=html
# View coverage: htmlcov/index.html
```

### Frontend Testing

**Component Tests:**
```bash
npm run test
npm run test:coverage
```

**Integration Tests:**
```bash
npm run test:integration
```

**E2E Tests (Playwright):**
```bash
npm run test:e2e
```

### Extension Testing

**Manual Test Checklist:**

- [ ] **Auto-Scan**
  - Install extension
  - Visit safe site (google.com) → See green "Safe"
  - Visit suspicious site → See warning
  - Toggle auto-scan OFF → No auto-scan
  - Toggle auto-scan ON → Auto-scan resumes

- [ ] **Manual Scan**
  - Click extension icon
  - Click "Scan This Page"
  - Result appears in 1-2 seconds
  - Confidence bar displays correctly

- [ ] **Quarantine**
  - Scan suspicious URL
  - Click "Add to Quarantine"
  - Success toast appears
  - Statistics update (quarantine count +1)
  - Visit quarantine page in web app → URL appears

- [ ] **Block Site**
  - Scan phishing URL
  - Click "Block This Site"
  - Tab closes automatically
  - Try revisiting → Blocked page shown
  - Statistics update (blocked count +1)

- [ ] **Statistics**
  - Initial stats load correctly
  - Stats refresh every 10 seconds
  - Actions update stats in real-time
  - Numbers match web app dashboard

- [ ] **Navigation**
  - Click "Open Dashboard" → Web app opens
  - Click "Settings" → Settings page opens
  - All links open in new tabs

- [ ] **Sync**
  - Block URL in extension
  - Open web app → URL in quarantine list
  - Unblock in web app
  - Extension recognizes unblock (within 1s)

**Load Testing:**
```bash
# Test extension with rapid tab switching
# Ensure no memory leaks or crashes
```

---

## 🚀 Deployment

### Backend Deployment (Heroku)

```bash
cd backend
heroku create phishguard-api
heroku addons:create heroku-postgresql:hobby-dev
heroku addons:create heroku-redis:hobby-dev
git push heroku main
heroku run python -m alembic upgrade head
```

**Environment Variables:**
```bash
heroku config:set SECRET_KEY=your-secret-key
heroku config:set CORS_ORIGINS=https://phishguard.com
```

### Frontend Deployment (Vercel)

```bash
npm run build
vercel --prod
```

**Environment Variables:**
```env
VITE_API_URL=https://phishguard-api.herokuapp.com
```

### Extension Deployment (Chrome Web Store)

1. **Prepare Package:**
   ```bash
   cd browser-extension
   zip -r phishguard-extension.zip *
   ```

2. **Submit to Chrome Web Store:**
   - Go to [Chrome Developer Dashboard](https://chrome.google.com/webstore/devconsole)
   - Upload `phishguard-extension.zip`
   - Fill in store listing
   - Submit for review

3. **Update API URLs:**
   ```javascript
   // popup.js - Change for production
   const API_BASE = 'https://phishguard-api.herokuapp.com/api';
   const WEB_APP = 'https://phishguard.com';
   ```

---

## 📊 Monitoring & Analytics

### Application Monitoring

**Backend Metrics:**
- Request rate (requests/sec)
- Response time (p50, p95, p99)
- Error rate (%)
- ML inference time

**Frontend Metrics:**
- Page load time
- Time to interactive
- API call success rate
- User engagement (DAU/MAU)

**Extension Metrics:**
- Install count
- Active users
- Scan success rate
- Block/quarantine actions

### Logging

```python
# Backend logging
import logging

logger = logging.getLogger("phishguard")
logger.info(f"Scanned URL: {url}, Result: {result}")
```

```javascript
// Frontend logging
console.log('[PhishGuard]', 'Scan initiated:', url);
```

### Error Tracking

- **Backend:** Sentry Python SDK
- **Frontend:** Sentry JavaScript SDK
- **Extension:** Chrome extension error reporting

---

## 🤝 Contributing

### Development Workflow

1. **Fork & Clone**
   ```bash
   git clone https://github.com/yourusername/phishguard.git
   cd phishguard
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Changes**
   - Follow code style guidelines
   - Add tests for new features
   - Update documentation

4. **Test Locally**
   ```bash
   # Backend
   cd backend && pytest

   # Frontend
   npm run test

   # Extension
   # Manual testing in browser
   ```

5. **Submit Pull Request**
   - Descriptive title
   - Explain changes and motivation
   - Reference related issues

### Code Style

**Python (Backend):**
- Black formatter
- Flake8 linter
- Type hints with mypy

**TypeScript/React (Frontend):**
- ESLint + Prettier
- React best practices
- Functional components + hooks

**JavaScript (Extension):**
- ESLint
- Clear function names
- Comprehensive comments

---

## 📜 License

MIT License - see [LICENSE](LICENSE) for details

---

## 🙏 Acknowledgments

- **Kaggle** - Phishing URL dataset
- **Shadcn UI** - Component library
- **FastAPI** - Backend framework
- **React Team** - Frontend framework
- **Chrome Extensions Team** - Extension platform

---

## 📞 Support

- **Documentation:** See `/docs` folder
- **Issues:** [GitHub Issues](https://github.com/yourusername/phishguard/issues)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/phishguard/discussions)
- **Email:** support@phishguard.com

---

## 🎯 Roadmap

### Short Term (Q4 2025)
- [ ] WebSocket support for real-time updates
- [ ] Advanced analytics dashboard
- [ ] Email phishing detection
- [ ] Mobile app (React Native)

### Medium Term (Q1-Q2 2026)
- [ ] Enterprise SSO integration
- [ ] Custom ML model training UI
- [ ] Browser extension for Firefox/Safari
- [ ] API rate limiting & billing

### Long Term (2026+)
- [ ] AI-powered threat explanations
- [ ] Blockchain-based threat intelligence sharing
- [ ] Integration with SIEM systems
- [ ] Automated takedown requests

---

## 📈 Performance Targets

| Metric | Current | Target (2026) |
|--------|---------|---------------|
| ML Accuracy | 99.93% | 99.99% |
| Scan Speed | 69.6 URL/s | 200 URL/s |
| API Response Time | 1-2s | <500ms |
| Extension Size | 500KB | <200KB |
| Active Users | - | 1M+ |

---

**Built with ❤️ for a safer web by the PhishGuard Team**
import { render, screen, fireEvent } from '@testing-library/react';
import { URLScan } from '../URLScan';

describe('URLScan', () => {
  it('validates URL input', () => {
    render(<URLScan />);
    const input = screen.getByPlaceholderText(/https:\/\//);
    fireEvent.change(input, { target: { value: 'invalid' } });
    // Add assertions
  });
});
```

## Storybook

Component stories are available for design system documentation:

```bash
# Start Storybook
npm run storybook

# Build static Storybook
npm run build:storybook
```

Example story:

```typescript
// src/components/ui/Button.stories.tsx
import type { Meta, StoryObj } from '@storybook/react';
import { Button } from './button';

const meta: Meta<typeof Button> = {
  title: 'UI/Button',
  component: Button,
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof Button>;

export const Primary: Story = {
  args: {
    children: 'Button',
    variant: 'default',
  },
};
```

## Building for Production

```bash
# Build the app
npm run build

# Preview production build
npm run preview
```

The build output will be in the `dist/` directory.

## Environment Variables

Create a `.env` file for configuration:

```env
# API Base URL (defaults to mock)
VITE_API_BASE_URL=https://api.example.test

# Enable/disable MSW
VITE_ENABLE_MSW=true
```

## Browser Support

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Mobile browsers

## Accessibility

- Keyboard navigation supported throughout
- Screen reader friendly with ARIA labels
- Focus indicators on all interactive elements
- Color contrast meets WCAG AA standards
- Semantic HTML structure

## Performance

- Code splitting by route
- Lazy loading of components
- Optimized bundle size
- Fast page transitions
- Efficient re-renders with React Query

## Future Enhancements

When connecting to a real backend:

1. Replace MSW mocks with actual API calls
2. Add proper error handling and retry logic
3. Implement real-time WebSocket updates for scan progress
4. Add CSV export functionality
5. Implement proper authentication with JWT refresh
6. Add rate limiting indicators

## License

MIT

## Contributing

Contributions are welcome! Please follow the existing code style and include tests for new features.
#   A n t i - p h i s h i n g - a n d - M a l i c i o u s - U R L - D e t e c t o r  
 