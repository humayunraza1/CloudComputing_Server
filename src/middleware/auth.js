const jwt = require('jsonwebtoken');
const { db } = require('../db');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

exports.authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await db.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
    
    if (user.length === 0) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user[0];
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

exports.isAdmin = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await db.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
    
    if (user.length === 0) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (user[0].role !== 'admin' && user[0].role !== 'moderator') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    req.user = user[0];
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
}; 