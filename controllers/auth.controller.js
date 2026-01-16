const pool = require('../config/db.config');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const JWT_SECRET = process.env.JWT_SECRET;

exports.login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email dan password wajib diisi.' });
    }

    try {
        console.log('=== LOGIN ATTEMPT ===');
        console.log('Input email:', `"${email}"`);

        // Menggunakan BINARY untuk case-sensitive comparison di SQL
        const [rows] = await pool.execute(
            'SELECT email, nama_staff, password_hash FROM staff_tu WHERE BINARY email = ?',
            [email]
        );

        console.log('Query results:', rows.length, 'row(s) found');

        if (rows.length === 0) {
            console.log('❌ Email tidak ditemukan (BINARY check failed)');
            return res.status(401).json({ message: 'Email atau password salah.' });
        }

        const user = rows[0];

        console.log('Database email:', `"${user.email}"`);
        console.log('Input email:   ', `"${email}"`);
        console.log('Exact match?:', user.email === email);

        // DOUBLE CHECK: Validasi case-sensitive di JavaScript juga
        // Ini untuk memastikan meskipun BINARY di SQL tidak bekerja
        if (user.email !== email) {
            console.log('❌ Email tidak match persis (JavaScript validation failed)');
            console.log('   Database:', user.email);
            console.log('   Input:   ', email);
            return res.status(401).json({ message: 'Email atau password salah.' });
        }

        console.log('✅ Email match persis!');
        console.log('===================');

        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return res.status(401).json({ message: 'Email atau password salah.' });
        }

        const token = jwt.sign(
            { email: user.email },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({
            message: 'Login berhasil',
            token,
            user: {
                email: user.email,
                nama_staff: user.nama_staff
            }
        });

    } catch (error) {
        res.status(500).json({
            message: 'Server error saat login.',
            error: error.message
        });
    }
};