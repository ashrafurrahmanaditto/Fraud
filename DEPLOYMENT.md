# Deployment Guide

## Prerequisites

- Node.js 16+ installed
- Supabase account
- Git repository access

## Step 1: Supabase Setup

### Create Supabase Project

1. Go to [supabase.com](https://supabase.com)
2. Click "New Project"
3. Choose your organization
4. Enter project details:
   - Name: `url-shortener-fraud-detection`
   - Database Password: Generate a strong password
   - Region: Choose closest to your users
5. Click "Create new project"

### Configure Database

1. Wait for project setup to complete
2. Go to SQL Editor in your Supabase dashboard
3. Copy the entire contents of `supabase-schema.sql`
4. Paste and run the SQL script
5. Verify all tables and functions are created

### Get API Keys

1. Go to Settings > API
2. Copy the following values:
   - Project URL
   - anon/public key

## Step 2: Local Development

### Environment Setup

1. Clone the repository:
   ```bash
   git clone <your-repo-url>
   cd url-shortener-fraud-detection
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create environment file:
   ```bash
   cp env.example .env
   ```

4. Edit `.env` with your Supabase credentials:
   ```env
   REACT_APP_SUPABASE_URL=https://your-project.supabase.co
   REACT_APP_SUPABASE_ANON_KEY=your-anon-key
   ```

### Test Locally

1. Start the development server:
   ```bash
   npm start
   ```

2. Open `http://localhost:3000`
3. Test URL shortening functionality
4. Check admin dashboard at `http://localhost:3000/admin`

## Step 3: Frontend Deployment

### Option A: Vercel (Recommended)

1. Install Vercel CLI:
   ```bash
   npm install -g vercel
   ```

2. Login to Vercel:
   ```bash
   vercel login
   ```

3. Deploy:
   ```bash
   vercel --prod
   ```

4. Set environment variables in Vercel dashboard:
   - Go to your project settings
   - Add environment variables:
     - `REACT_APP_SUPABASE_URL`
     - `REACT_APP_SUPABASE_ANON_KEY`

### Option B: Netlify

1. Build the project:
   ```bash
   npm run build
   ```

2. Install Netlify CLI:
   ```bash
   npm install -g netlify-cli
   ```

3. Deploy:
   ```bash
   netlify deploy --prod --dir=build
   ```

4. Set environment variables in Netlify dashboard

### Option C: Manual Deployment

1. Build the project:
   ```bash
   npm run build
   ```

2. Upload the `build/` folder to your web server
3. Configure environment variables on your server

## Step 4: Domain Configuration

### Custom Domain (Optional)

1. **Vercel**:
   - Go to project settings
   - Add custom domain
   - Update DNS records

2. **Netlify**:
   - Go to domain settings
   - Add custom domain
   - Configure DNS

### Update Base URL

If using a custom domain, update the base URL in your components:

```typescript
// In RedirectHandler.tsx
const shortUrl = `${window.location.origin}/${shortCode}`
```

## Step 5: Security Configuration

### Supabase Security

1. **Enable RLS**: Already configured in schema
2. **API Keys**: Use anon key for public access
3. **Database Security**: Review and adjust RLS policies as needed

### Environment Security

1. **Never commit** `.env` files
2. **Use environment variables** in production
3. **Rotate keys** regularly
4. **Monitor usage** in Supabase dashboard

## Step 6: Monitoring Setup

### Supabase Monitoring

1. Go to Dashboard > Logs
2. Monitor API usage and errors
3. Set up alerts for unusual activity

### Application Monitoring

1. **Error Tracking**: Consider adding Sentry
2. **Analytics**: Add Google Analytics if needed
3. **Performance**: Monitor Core Web Vitals

## Step 7: Production Optimization

### Performance

1. **Enable CDN**: Vercel/Netlify provide automatic CDN
2. **Image Optimization**: Use WebP format
3. **Code Splitting**: Already implemented with React

### Security

1. **HTTPS**: Ensure SSL certificates
2. **Headers**: Configure security headers
3. **CORS**: Configure if needed

## Troubleshooting

### Common Deployment Issues

1. **Build Failures**:
   ```bash
   npm run build
   # Check for TypeScript errors
   ```

2. **Environment Variables**:
   - Verify all required variables are set
   - Check for typos in variable names

3. **Supabase Connection**:
   - Verify project URL and keys
   - Check network connectivity
   - Review Supabase logs

4. **Database Issues**:
   - Verify schema was applied correctly
   - Check RLS policies
   - Review function definitions

### Debug Mode

Enable debug logging in production:

```env
REACT_APP_DEBUG=true
```

### Health Checks

Create a health check endpoint:

```typescript
// Add to your app
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() })
})
```

## Maintenance

### Regular Tasks

1. **Monitor Usage**: Check Supabase dashboard weekly
2. **Update Dependencies**: Monthly security updates
3. **Review Logs**: Check for errors and suspicious activity
4. **Backup Data**: Supabase handles automatic backups

### Scaling Considerations

1. **Database**: Supabase scales automatically
2. **CDN**: Vercel/Netlify provide global CDN
3. **Rate Limiting**: Adjust limits based on usage
4. **Monitoring**: Add more detailed metrics as needed

## Support

### Getting Help

1. **Documentation**: Check Supabase and FingerprintJS docs
2. **Community**: GitHub issues and discussions
3. **Professional Support**: Consider paid support for production

### Useful Resources

- [Supabase Documentation](https://supabase.com/docs)
- [FingerprintJS Documentation](https://dev.fingerprintjs.com/)
- [React Deployment Guide](https://create-react-app.dev/docs/deployment/)
- [Vercel Documentation](https://vercel.com/docs)
- [Netlify Documentation](https://docs.netlify.com/)
