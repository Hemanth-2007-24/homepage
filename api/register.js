// FILENAME: api/register.js
import bcrypt from 'bcryptjs';
import { db } from './_db.js';
import { issueToken, setAuthCookie } from './_utils.js';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method Not Allowed' });
    }

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Name, email, and password are required.' });
    }

    const existingUser = db.users.findOne(user => user.email === email);
    if (existingUser) {
        return res.status(409).json({ message: 'Email is already in use.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    
    const newUser = db.users.create({
        name,
        email,
        passwordHash,
        provider: 'manual'
    });

    const token = issueToken(newUser);
    setAuthCookie(res, token);
    
    res.status(201).json({ success: true, user: { id: newUser.id, name: newUser.name, email: newUser.email } });
}