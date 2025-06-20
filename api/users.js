// FILENAME: api/users.js
import { parse } from 'cookie';
import { db } from './_db.js';
import { verifyToken } from './_utils.js';

export default async function handler(req, res) {
    // 1. Get token from cookies or Authorization header
    let token;
    const cookies = parse(req.headers.cookie || '');
    if (cookies.authToken) {
        token = cookies.authToken;
    } else if (req.headers.authorization) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Authentication required.' });
    }

    // 2. Verify the token
    const payload = verifyToken(token);
    if (!payload) {
        return res.status(401).json({ message: 'Invalid or expired token.' });
    }

    // 3. Check if the user is an admin
    if (payload.role !== 'admin') {
        return res.status(403).json({ message: 'Forbidden. Admin access required.' });
    }

    // 4. Return all users (excluding sensitive data like password hashes)
    const allUsers = db.users.getAll().map(({ passwordHash, ...user }) => user);
    res.status(200).json(allUsers);
}