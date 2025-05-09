const { verifyAccessToken, verifyRefreshToken } = require('../utils/auth');
const sql = require('mssql');
const { dbConfig } = require('../config/database');

const authenticate = async (req, res, next) => {
    try {
        const accessToken = req.cookies.accessToken;
        const refreshToken = req.cookies.refreshToken;

        if (!accessToken) {
            return res.status(401).json({ error: 'No access token provided' });
        }

        // Verify access token
        const decoded = verifyAccessToken(accessToken);
    
        if (decoded) {
            req.user = decoded;
            return next();
        }

        // If access token is expired, try to refresh
        if (!refreshToken) {
            return res.status(401).json({ error: 'No refresh token provided' });
        }

        const refreshDecoded = verifyRefreshToken(refreshToken);
        if (!refreshDecoded) {
            return res.status(401).json({ error: 'Invalid refresh token' });
        }

        // Get user from database
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('userId', sql.Int, refreshDecoded.userId)
            .query('SELECT * FROM Users WHERE user_id = @userId');

        if (result.recordset.length === 0) {
            return res.status(401).json({ error: 'User not found' });
        }

        const user = result.recordset[0];

        // Generate new tokens
        const { generateTokens } = require('../utils/auth');
        const tokens = generateTokens(user);

        // Set new cookies
        res.cookie('accessToken', tokens.accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        });

        res.cookie('refreshToken', tokens.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        req.user = {
            userId: user.user_id,
            role: user.role,
            email: user.email
        };

        next();
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).json({ error: 'Authentication failed' });
    }
};

const checkRole = (roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Authentication required' });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Access denied. Insufficient permissions.' });
        }

        next();
    };
};

module.exports = {
    authenticate,
    checkRole
}; 