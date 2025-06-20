// FILENAME: api/_utils.js
import jwt from 'jsonwebtoken';
import { serialize } from 'cookie';

const JWT_SECRET = process.env.JWT_SECRET || 'a-very-secret-string-for-development';

export function issueToken(user) {
    const payload = {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role || 'user', // Ensure role is included
    };
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' });
}

export function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (e) {
        return null;
    }
}

export function setAuthCookie(res, token) {
    const cookie = serialize('authToken', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV !== 'development',
        sameSite: 'strict',
        maxAge: 60 * 60 * 24, // 1 day
        path: '/',
    });
    res.setHeader('Set-Cookie', cookie);
}

export function clearAuthCookie(res) {
    const cookie = serialize('authToken', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV !== 'development',
        sameSite: 'strict',
        expires: new Date(0), // Expire immediately
        path: '/',
    });
    res.setHeader('Set-Cookie', cookie);
}