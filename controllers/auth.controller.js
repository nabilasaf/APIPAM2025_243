const pool = require('../config/db.config');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt'); 
const JWT_SECRET = process.env.JWT_SECRET;

exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const [rows] = await pool.execute(
            'SELECT email, nama_staff, password_hash FROM staff_tu WHERE email = ?', 
            [email]
        );
        if (rows.length === 0) {
            return res.status(401).json({ message: 'Email atau password salah.' });
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ message: 'Email atau password salah.' });
        }
        const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ 
            message: 'Login berhasil',
            token: token,
            user: user.nama_staff 
        });
        
    } catch (error) {
        res.status(500).json({ message: 'Server Error saat Login.', error: error.message });
    }
};

exports.getProfile = async (req, res) => {
    const emailFromToken = req.user.email; 

    try {
        const [rows] = await pool.execute(
            'SELECT email, nama_staff FROM staff_tu WHERE email = ?', 
            [emailFromToken]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: 'User tidak ditemukan.' });
        }

        res.status(200).json({
            email: rows[0].email, 
            nama_staff: rows[0].nama_staff 
        });
    } catch (error) {
        res.status(500).json({ message: 'Gagal mengambil profil.', error: error.message });
    }
};