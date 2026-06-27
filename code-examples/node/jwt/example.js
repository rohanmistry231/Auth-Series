const jwt = require('jsonwebtoken');

// NEVER hardcode secrets in real code
const ACCESS_SECRET = 'your-256-bit-secret-minimum';
const REFRESH_SECRET = 'your-refresh-secret-must-be-different';

function generateTokens(userId, role) {
  const accessToken = jwt.sign(
    { sub: userId, role, type: 'access' },
    ACCESS_SECRET,
    { expiresIn: '15m', issuer: 'auth-series' }
  );

  const refreshToken = jwt.sign(
    { sub: userId, type: 'refresh' },
    REFRESH_SECRET,
    { expiresIn: '7d', issuer: 'auth-series' }
  );

  return { accessToken, refreshToken };
}

function verifyAccessToken(token) {
  try {
    const payload = jwt.verify(token, ACCESS_SECRET, {
      issuer: 'auth-series',
      algorithms: ['HS256']
    });
    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

// Demo
const tokens = generateTokens('user_123', 'admin');
console.log('Access Token:', tokens.accessToken);
console.log('Refresh Token:', tokens.refreshToken);
console.log('Decoded:', jwt.decode(tokens.accessToken));
console.log('Verified:', verifyAccessToken(tokens.accessToken));
