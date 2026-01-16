// routes/master.routes.js (UPDATE)

const express = require('express');
const router = express.Router();
const pool = require('../config/db.config');
const masterController = require('../controllers/master.controller');
const authController = require('../controllers/auth.controller'); // Import Auth Controller
const authMiddleware = require('../middleware/auth.middleware'); // Import Middleware

// --- ROUTE AUTHENTICATION ---
router.post('/auth/login', authController.login);


// --- ROUTE CRUD MASTER (DILINDUNGI) ---
// Terapkan middleware JWT ke semua route master
router.use(authMiddleware.verifyToken);

// POST /api/master/create 
router.post('/master/create', masterController.createSimultaneousData);

// GET /api/master/list 
router.get('/master/list', masterController.findAllSimultaneousData);

// GET /api/master/detail/:id_master (BARU)
router.get('/master/detail/:id_master', masterController.findSimultaneousDataById);

// PUT /api/master/update/:id_master (BARU)
router.put('/master/update/:id_master', masterController.updateSimultaneousData);

// DELETE /api/master/delete/:id_master 
router.delete('/master/delete/:id_master', masterController.deleteSimultaneousData);

// GET /api/master/profile (BARU)
router.get('/master/profile', async (req, res) => {
    try {
        const email = req.user.email; // Diambil dari JWT Token
        // Melakukan query ke tabel staff_tu berdasarkan email
        const [rows] = await pool.execute(
            'SELECT email, nama_staff FROM staff_tu WHERE email = ?',
            [email]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: 'User tidak ditemukan.' });
        }

        // Kirim data lengkap ke Android agar sesuai dengan StaffResponse
        res.status(200).json(rows[0]);
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error: error.message });
    }
});
module.exports = router;