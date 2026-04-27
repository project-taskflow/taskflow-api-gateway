require('dotenv').config();
const express = require('express');
const proxy = require('express-http-proxy');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const axios = require('axios');

const { authenticate } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;

const AUTH_SERVICE_URL         = process.env.AUTH_SERVICE_URL         || 'http://localhost:3001';
const USER_SERVICE_URL         = process.env.USER_SERVICE_URL         || 'http://localhost:3002';
const TASK_SERVICE_URL         = process.env.TASK_SERVICE_URL         || 'http://localhost:3003';
const NOTIFICATION_SERVICE_URL = process.env.NOTIFICATION_SERVICE_URL || 'http://localhost:3004';
const ANALYTICS_SERVICE_URL    = process.env.ANALYTICS_SERVICE_URL    || 'http://localhost:3005';

// Security
app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:5173', credentials: true }));
app.use(morgan('combined'));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 500, message: { error: 'Too many requests' } }));

// Helper: inject verified user headers for downstream services
const injectUser = (proxyReqOpts, srcReq) => {
  ['x-user-id', 'x-user-email', 'x-user-role', 'x-user-name'].forEach((h) => {
    if (srcReq.headers[h]) proxyReqOpts.headers[h] = srcReq.headers[h];
  });
  return proxyReqOpts;
};

const proxyError = (service) => (err, res) => {
  console.error(`${service} proxy error:`, err.message);
  res.status(502).json({ error: `${service} unavailable` });
};

// ── Public routes (no JWT) ────────────────────────────────────────────────────
app.use('/api/auth', proxy(AUTH_SERVICE_URL, {
  proxyReqPathResolver: (req) => `/auth${req.url}`,
  proxyErrorHandler: proxyError('auth-service'),
}));

// ── Protected routes (JWT required) ──────────────────────────────────────────
app.use('/api/users', authenticate, proxy(USER_SERVICE_URL, {
  proxyReqPathResolver: (req) => `/users${req.url}`,
  proxyReqOptDecorator: injectUser,
  proxyErrorHandler: proxyError('user-service'),
}));

app.use('/api/tasks', authenticate, proxy(TASK_SERVICE_URL, {
  proxyReqPathResolver: (req) => `/tasks${req.url}`,
  proxyReqOptDecorator: injectUser,
  proxyErrorHandler: proxyError('task-service'),
}));

app.use('/api/notifications', authenticate, proxy(NOTIFICATION_SERVICE_URL, {
  proxyReqPathResolver: (req) => `/notifications${req.url}`,
  proxyReqOptDecorator: injectUser,
  proxyErrorHandler: proxyError('notification-service'),
}));

app.use('/api/analytics', authenticate, proxy(ANALYTICS_SERVICE_URL, {
  proxyReqPathResolver: (req) => `/analytics${req.url}`,
  proxyReqOptDecorator: injectUser,
  proxyErrorHandler: proxyError('analytics-service'),
}));

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  const services = {
    'auth-service':         AUTH_SERVICE_URL,
    'user-service':         USER_SERVICE_URL,
    'task-service':         TASK_SERVICE_URL,
    'notification-service': NOTIFICATION_SERVICE_URL,
    'analytics-service':    ANALYTICS_SERVICE_URL,
  };

  const checks = await Promise.allSettled(
    Object.entries(services).map(async ([name, url]) => {
      const resp = await axios.get(`${url}/health`, { timeout: 3000 });
      return { name, status: resp.data.status };
    })
  );

  const results = checks.map((r, i) => ({
    service: Object.keys(services)[i],
    status: r.status === 'fulfilled' ? r.value.status : 'down',
  }));

  const allUp = results.every((s) => s.status === 'ok');
  res.status(allUp ? 200 : 207).json({ gateway: 'ok', services: results });
});

app.use((req, res) => res.status(404).json({ error: 'Route not found' }));

app.listen(PORT, () => console.log(`API Gateway running on port ${PORT}`));
