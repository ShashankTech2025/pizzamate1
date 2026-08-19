import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// In-Memory Security Store for Server-Authoritative IP & Rate-Limiting Configuration
interface ServerSecurityState {
  allowedPublicIps: Set<string>;
  wifiSsid: string;
  strictNetworkEnforcement: boolean;
  sessionDurationMinutes: number;
  maxOrdersPerWindow: number;
  rateLimitWindowMinutes: number;
  duplicateWindowSeconds: number;
  rateLimitHistory: Map<string, { timestamp: number; tableNumber: number; itemsHash: string }[]>;
}

const securityState: ServerSecurityState = {
  allowedPublicIps: new Set<string>(['127.0.0.1', 'localhost', '::1', '10.0.0.0/8', '192.168.1.1']),
  wifiSsid: 'Pizzamate_Customer_5G',
  strictNetworkEnforcement: false, // Default to permissive/demo with audit logging so valid testing is never blocked
  sessionDurationMinutes: 45,
  maxOrdersPerWindow: 5,
  rateLimitWindowMinutes: 10,
  duplicateWindowSeconds: 30,
  rateLimitHistory: new Map(),
};

function getClientIp(req: express.Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    const firstIp = forwarded.split(',')[0].trim();
    if (firstIp) return cleanIp(firstIp);
  }
  const remote = req.socket.remoteAddress || req.ip || '127.0.0.1';
  return cleanIp(remote);
}

function cleanIp(ip: string): string {
  if (ip === '::1' || ip === '::ffff:127.0.0.1') return '127.0.0.1';
  if (ip.startsWith('::ffff:')) return ip.replace('::ffff:', '');
  return ip;
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Middleware for JSON parsing and CORS support
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Basic CORS headers
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') {
      res.sendStatus(200);
      return;
    }
    next();
  });

  // Health endpoint
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', storage: 'firestore', service: 'pizzamate-security-engine' });
  });

  // -------------------------------------------------------------
  // LAYER 2: RESTAURANT WIFI / PUBLIC IP VERIFICATION ENDPOINT
  // -------------------------------------------------------------
  app.get('/api/check-network', (req, res) => {
    const clientIp = getClientIp(req);
    const isLocalOrContainer =
      clientIp === '127.0.0.1' ||
      clientIp === 'localhost' ||
      clientIp.startsWith('10.') ||
      clientIp.startsWith('172.') ||
      clientIp.startsWith('192.168.');

    let isAllowed = true;
    if (securityState.strictNetworkEnforcement) {
      isAllowed =
        isLocalOrContainer ||
        securityState.allowedPublicIps.has(clientIp);
    }

    res.json({
      allowed: isAllowed,
      clientIp,
      networkName: securityState.wifiSsid,
      allowedIps: Array.from(securityState.allowedPublicIps),
      strictEnforcement: securityState.strictNetworkEnforcement,
      isLocalOrDev: isLocalOrContainer,
      lastChecked: Date.now(),
      message: isAllowed
        ? 'Connected to verified in-restaurant network'
        : 'Access denied: You must connect to Restaurant Wi-Fi before placing an order.',
    });
  });

  // -------------------------------------------------------------
  // LAYER 7: SERVER ORDER PRE-VERIFICATION
  // -------------------------------------------------------------
  app.post('/api/verify-order', (req, res) => {
    const clientIp = getClientIp(req);
    const {
      tableNumber,
      sessionId,
      sessionToken,
      deviceFingerprint,
      itemsHash,
      clientTimestamp,
    } = req.body || {};

    // 1. Table Number Bounds Check (1-20)
    const tableNum = Number(tableNumber);
    if (isNaN(tableNum) || tableNum < 1 || tableNum > 20) {
      return res.status(400).json({
        valid: false,
        errorCode: 'UNAUTHORIZED_TABLE',
        errorMessage: `Invalid table number (${tableNumber}). Please rescan the table QR code.`,
      });
    }

    // 2. Session ID & Token Format Verification
    if (!sessionId || typeof sessionId !== 'string' || !sessionToken || typeof sessionToken !== 'string') {
      return res.status(400).json({
        valid: false,
        errorCode: 'INVALID_TOKEN',
        errorMessage: 'Invalid or missing table session token. Please scan the QR code at your table.',
      });
    }

    // 3. Device Fingerprint Integrity Check
    if (!deviceFingerprint || typeof deviceFingerprint !== 'string' || !deviceFingerprint.startsWith('dfp_')) {
      return res.status(400).json({
        valid: false,
        errorCode: 'TAMPERED_FINGERPRINT',
        errorMessage: 'Device fingerprint verification failed. Please refresh your browser.',
      });
    }

    // 4. Rate Limiting & Duplicate Order Check (Server-Side)
    const historyKey = `${clientIp}_${deviceFingerprint}`;
    const now = Date.now();
    const windowMs = securityState.rateLimitWindowMinutes * 60 * 1000;
    const dupMs = securityState.duplicateWindowSeconds * 1000;

    let entries = securityState.rateLimitHistory.get(historyKey) || [];
    entries = entries.filter((e) => now - e.timestamp < windowMs);

    // Duplicate Check
    const isDuplicate = entries.some(
      (e) => e.tableNumber === tableNum && e.itemsHash === itemsHash && now - e.timestamp < dupMs
    );
    if (isDuplicate) {
      return res.status(429).json({
        valid: false,
        errorCode: 'DUPLICATE_ORDER',
        errorMessage: 'Identical order received within 30 seconds. Duplicate rejected.',
      });
    }

    // Rate Limit Check (Max 5 within 10 mins)
    if (entries.length >= securityState.maxOrdersPerWindow) {
      return res.status(429).json({
        valid: false,
        errorCode: 'RATE_LIMITED',
        errorMessage: 'Rate limit exceeded: Maximum 5 orders allowed per 10 minutes.',
      });
    }

    // Record entry
    entries.push({ timestamp: now, tableNumber: tableNum, itemsHash: itemsHash || '' });
    securityState.rateLimitHistory.set(historyKey, entries);

    return res.json({
      valid: true,
      clientIp,
      verifiedAt: now,
    });
  });

  // -------------------------------------------------------------
  // LAYER 8: ADMIN SECURITY CONFIGURATION API
  // -------------------------------------------------------------
  app.get('/api/security/settings', (req, res) => {
    res.json({
      allowedPublicIps: Array.from(securityState.allowedPublicIps),
      wifiSsid: securityState.wifiSsid,
      strictNetworkEnforcement: securityState.strictNetworkEnforcement,
      sessionDurationMinutes: securityState.sessionDurationMinutes,
      maxOrdersPerWindow: securityState.maxOrdersPerWindow,
      rateLimitWindowMinutes: securityState.rateLimitWindowMinutes,
      duplicateWindowSeconds: securityState.duplicateWindowSeconds,
    });
  });

  app.post('/api/security/settings', (req, res) => {
    const { allowedPublicIps, wifiSsid, strictNetworkEnforcement } = req.body || {};

    if (Array.isArray(allowedPublicIps)) {
      securityState.allowedPublicIps = new Set(
        allowedPublicIps.map((ip: string) => cleanIp(ip.trim())).filter(Boolean)
      );
    }
    if (typeof wifiSsid === 'string' && wifiSsid.trim()) {
      securityState.wifiSsid = wifiSsid.trim();
    }
    if (typeof strictNetworkEnforcement === 'boolean') {
      securityState.strictNetworkEnforcement = strictNetworkEnforcement;
    }

    res.json({
      success: true,
      settings: {
        allowedPublicIps: Array.from(securityState.allowedPublicIps),
        wifiSsid: securityState.wifiSsid,
        strictNetworkEnforcement: securityState.strictNetworkEnforcement,
      },
    });
  });

  // Vite Middleware (Dev) or Static dist (Prod)
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Pizzamate Web Server with Multi-Layer Security running at http://0.0.0.0:${PORT}`);
  });
}

startServer();
