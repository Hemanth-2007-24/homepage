// FILENAME: /api/users.js

const jwt = require('jsonwebtoken');
const { users, JWT_SECRET } = require('./_data');

module.exports = async (req, res) => {
    if (req.method !== 'GET') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'Unauthorized: No token provided.' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);

        if (decoded.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden: You do not have admin privileges.' });
        }

        // Return all users, but without their password hashes
        const safeUsers = users.map(u => ({ id: u.id, name: u.name, email: u.email, provider: u.provider }));
        
        return res.status(200).json(safeUsers);

    } catch (error) {
        if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Unauthorized: Invalid token.' });
        }
        console.error('FETCH USERS ERROR:', error);
        return res.status(500).json({ message: 'A server error occurred.' });
    }
};