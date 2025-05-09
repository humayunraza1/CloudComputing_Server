const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key';

const generateTokens = (user) => {
    const accessToken = jwt.sign(
        { 
            userId: user.id,
            role: user.role,
            email: user.email 
        },
        JWT_SECRET,
        { expiresIn: '1d' }
    );

    const refreshToken = jwt.sign(
        { 
            userId: user.user_id,
            tokenVersion: user.token_version || 0
        },
        JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
    );

    return { accessToken, refreshToken };
};

const verifyAccessToken = (token) => {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
};

const verifyRefreshToken = (token) => {
    try {
        return jwt.verify(token, JWT_REFRESH_SECRET);
    } catch (error) {
        return null;
    }
};

module.exports = {
    generateTokens,
    verifyAccessToken,
    verifyRefreshToken
}; 