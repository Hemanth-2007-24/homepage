// FILENAME: /api/users.js
import jwt from 'jsonwebtoken';
import { supabase } from './_supabase.js';

const JWT_SECRET = process.env.JWT_SECRET;

export default async function handler(req, res) {
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

        const { data: users, error } = await supabase
            .from('users')
            .select('id, name, email, provider, role'); // Select only safe fields

        if (error) throw error;
        
        return res.status(200).json(users);

    } catch (error) {
        if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Unauthorized: Invalid token.' });
        }
        console.error('FETCH USERS ERROR:', error);
        return res.status(500).json({ message: 'A server error occurred.' });
    }
}