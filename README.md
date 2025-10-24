# URL Shortener with Fraud Detection

A comprehensive URL shortener web application built with React, Supabase, and FingerprintJS that includes advanced fraud detection capabilities.

## Features

- **URL Shortening**: Create short URLs with custom codes
- **Device Fingerprinting**: Track devices using FingerprintJS
- **Fraud Detection**: Advanced risk scoring and suspicious activity detection
- **Real-time Monitoring**: Live admin dashboard with real-time updates
- **Rate Limiting**: Prevent abuse with configurable rate limits
- **Risk Logging**: Comprehensive logging of suspicious activities
- **Responsive Design**: Modern UI built with Tailwind CSS

## Tech Stack

- **Frontend**: React 18, TypeScript, Tailwind CSS
- **Backend**: Supabase (PostgreSQL, Real-time, Auth)
- **Fingerprinting**: FingerprintJS v4
- **Deployment**: Vercel/Netlify (Frontend), Supabase (Backend)

## Quick Start

### 1. Clone and Install

```bash
git clone <repository-url>
cd url-shortener-fraud-detection
npm install
```

### 2. Set up Supabase

1. Create a new project at [supabase.com](https://supabase.com)
2. Go to Settings > API and copy your project URL and anon key
3. Create a `.env` file in the root directory:

```env
REACT_APP_SUPABASE_URL=your_supabase_project_url
REACT_APP_SUPABASE_ANON_KEY=your_supabase_anon_key
```

### 3. Database Setup

1. Open your Supabase project dashboard
2. Go to SQL Editor
3. Copy and paste the contents of `supabase-schema.sql`
4. Run the SQL to create all tables, functions, and policies

### 4. Run the Application

```bash
npm start
```

The application will be available at `http://localhost:3000`

## Project Structure

```
src/
├── components/
│   ├── UrlShortener.tsx      # Main URL shortening interface
│   ├── AdminDashboard.tsx    # Admin dashboard with real-time updates
│   └── RedirectHandler.tsx    # Handles URL redirects and visit tracking
├── lib/
│   ├── supabase.ts          # Supabase client and types
│   ├── fingerprint.ts       # FingerprintJS integration
│   └── fraudDetection.ts    # Fraud detection utilities
├── App.tsx                  # Main app component with routing
└── index.tsx               # App entry point
```

## Database Schema

### Tables

- **fingerprints**: Stores device fingerprints and risk scores
- **urls**: Stores shortened URLs and metadata
- **url_visits**: Tracks every URL visit with fingerprint data
- **risk_logs**: Logs suspicious activities and fraud attempts
- **rate_limits**: Implements rate limiting per fingerprint
- **users**: Optional user accounts (for future authentication)

### Key Functions

- `generate_short_code()`: Generates unique short codes
- `calculate_risk_score()`: Calculates device risk scores
- `check_rate_limit()`: Implements rate limiting
- `update_risk_score()`: Auto-updates risk scores via triggers

## Fraud Detection Features

### Risk Scoring System

Devices are scored on a 0-10 scale based on:

- **URL Creation Volume**: Multiple URLs from same device
- **Visit Patterns**: Unusual click patterns
- **Duplicate Fingerprints**: Same visitor_id across multiple records
- **Suspicious URLs**: Known spam domains and patterns
- **Rate Limiting Violations**: Exceeding allowed limits

### Detection Patterns

- **Spam Domains**: Known URL shorteners and suspicious domains
- **Rapid Creation**: Multiple URLs created in short timeframes
- **High Volume**: Excessive URL creation or visits
- **Pattern Analysis**: Unusual URL structures and patterns

### Real-time Monitoring

The admin dashboard provides:

- **Live Statistics**: Total URLs, visits, high-risk devices
- **Recent Activity**: Latest URLs, visits, and risk events
- **Device Management**: View and monitor high-risk devices
- **Risk Logs**: Detailed logs of suspicious activities

## API Endpoints

### Supabase Functions

- `check_rate_limit(fingerprint_uuid, action_type, max_attempts, window_minutes)`
- `calculate_risk_score(fingerprint_uuid)`
- `generate_short_code()`

### Real-time Subscriptions

- **urls**: New URL creation events
- **visits**: New visit tracking events
- **risk_logs**: New risk event notifications

## Deployment

### Frontend (Vercel/Netlify)

1. **Vercel**:
   ```bash
   npm install -g vercel
   vercel --prod
   ```

2. **Netlify**:
   ```bash
   npm run build
   # Upload dist/ folder to Netlify
   ```

### Environment Variables

Set these in your deployment platform:

- `REACT_APP_SUPABASE_URL`
- `REACT_APP_SUPABASE_ANON_KEY`

### Backend (Supabase)

The backend is already deployed with Supabase. No additional deployment needed.

## Security Considerations

### Row Level Security (RLS)

- Public access for URL creation and visiting
- Admin-only access for sensitive data
- Proper authentication checks

### Rate Limiting

- Configurable limits per action type
- Time-window based restrictions
- Automatic cleanup of old entries

### Data Privacy

- Fingerprint data is anonymized
- No personal information stored
- GDPR-compliant data handling

## Monitoring and Alerts

### Admin Dashboard Features

- **Real-time Updates**: Live data via Supabase Realtime
- **Risk Monitoring**: High-risk device tracking
- **Activity Logs**: Comprehensive audit trail
- **Statistics**: Usage metrics and trends

### Alert System

- **Risk Events**: Automatic logging of suspicious activities
- **Email Notifications**: Configurable alerts for high-risk events
- **Dashboard Notifications**: Real-time toast notifications

## Customization

### Rate Limits

Modify rate limits in `src/lib/fraudDetection.ts`:

```typescript
const limits = {
  maxAttempts: 10,    // URLs per hour
  windowMinutes: 60   // Time window
}
```

### Risk Scoring

Adjust risk scoring thresholds in `supabase-schema.sql`:

```sql
-- Modify the calculate_risk_score function
-- Adjust thresholds for different risk levels
```

### UI Customization

- Modify Tailwind classes in components
- Update color schemes in `tailwind.config.js`
- Customize dashboard layout and metrics

## Troubleshooting

### Common Issues

1. **FingerprintJS not loading**: Check for ad blockers or network issues
2. **Supabase connection errors**: Verify environment variables
3. **Rate limiting too strict**: Adjust limits in database functions
4. **Real-time not working**: Check Supabase Realtime settings

### Debug Mode

Enable debug logging by adding to `.env`:

```env
REACT_APP_DEBUG=true
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

For issues and questions:

1. Check the troubleshooting section
2. Review Supabase documentation
3. Check FingerprintJS documentation
4. Open an issue in the repository

## Roadmap

- [ ] User authentication system
- [ ] Custom domain support
- [ ] Analytics and reporting
- [ ] API endpoints for external integration
- [ ] Advanced fraud detection ML models
- [ ] Email notification system
- [ ] Mobile app support
