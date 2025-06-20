// FILENAME: api/login.js
import bcrypt from 'bcryptjs';
import { db } from './_db.js';
import { issueToken, setAuthCookie } from './_utils.js';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    const user = db.users.findOne(u => u.email === email && u.provider === 'manual');
    if (!user) {
        return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
        return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const token = issueToken(user);
    setAuthCookie(res, token);
    
    res.status(200).json({ success: true });
}