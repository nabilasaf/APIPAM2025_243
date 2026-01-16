const pool = require('../config/db.config');

const executeTransaction = async (queries) => {
    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        const results = [];
        for (const { sql, values } of queries) {
            const [rows] = await connection.execute(sql, values);
            results.push(rows);
        }
        await connection.commit();
        return results;
    } catch (error) {
        await connection.rollback();
        throw error;
    } finally {
        connection.release();
    }
};

// CREATE
exports.createSimultaneousData = async (req, res) => {
    const { 
        nim, nama_lengkap, 
        kode_mk, nama_mk, sks, 
        nip_nik, nama_dosen, jabatan 
    } = req.body;
    
    const input_by_email = req.user.email; 

    try {
        // Insert ke tabel transaksi_master terlebih dahulu
        const [masterResult] = await pool.execute(
            'INSERT INTO transaksi_master (input_by_email) VALUES (?)', 
            [input_by_email]
        );
        const id_master = masterResult.insertId;

        // Insert ke tabel
        await Promise.all([
            pool.execute(
                'INSERT INTO asisten_dosen (id_master, nim, nama_lengkap, status_aktif_asdos) VALUES (?, ?, ?, ?)',
                [id_master, nim, nama_lengkap, 1] 
            ),
            pool.execute(
                'INSERT INTO mata_kuliah (id_master, kode_mk, nama_mk, sks) VALUES (?, ?, ?, ?)',
                [id_master, kode_mk, nama_mk, sks]
            ),
            pool.execute(
                'INSERT INTO dosen_koordinator (id_master, nip_nik, nama_dosen, jabatan) VALUES (?, ?, ?, ?)',
                [id_master, nip_nik, nama_dosen, jabatan]
            )
        ]);

        res.status(201).json({ message: "Data berhasil disimpan ke semua tabel." });
    } catch (error) {
        res.status(500).json({ message: "Gagal simpan", error: error.message }); 
    }
};

// READ ALL
exports.findAllSimultaneousData = async (req, res) => {
    const sql = `
        SELECT TM.id_master, AD.nim, AD.nama_lengkap, MK.kode_mk, MK.nama_mk, 
               DK.nip_nik, DK.nama_dosen, TM.tanggal_transaksi
        FROM transaksi_master TM
        JOIN asisten_dosen AD ON TM.id_master = AD.id_master
        JOIN mata_kuliah MK ON TM.id_master = MK.id_master
        JOIN dosen_koordinator DK ON TM.id_master = DK.id_master
        ORDER BY TM.tanggal_transaksi DESC`;

    try {
        const [rows] = await pool.execute(sql);
        res.status(200).json({ data: rows }); 
    } catch (error) {
        res.status(500).json({ message: "Gagal mengambil data dashboard.", error: error.message });
    }
};

// DELETE
exports.deleteSimultaneousData = async (req, res) => {
    const { id_master } = req.params;
    try {
        const [result] = await pool.execute('DELETE FROM transaksi_master WHERE id_master = ?', [id_master]);
        if (result.affectedRows === 0) return res.status(404).json({ message: "Data tidak ditemukan." });
        res.status(200).json({ message: "Data berhasil dihapus." });
    } catch (error) {
        res.status(500).json({ message: "Gagal menghapus data.", error: error.message });
    }
};

// READ DETAIL BY ID
exports.findSimultaneousDataById = async (req, res) => {
    const { id_master } = req.params;
    const sql = `
        SELECT AD.*, MK.*, DK.*, TM.tanggal_transaksi
        FROM transaksi_master TM
        JOIN asisten_dosen AD ON TM.id_master = AD.id_master
        JOIN mata_kuliah MK ON TM.id_master = MK.id_master
        JOIN dosen_koordinator DK ON TM.id_master = DK.id_master
        WHERE TM.id_master = ?`;

    try {
        const [rows] = await pool.execute(sql, [id_master]);
        if (rows.length === 0) return res.status(404).json({ message: "Data tidak ditemukan." });
        
        res.status(200).json({ data: rows[0] }); 
    } catch (error) {
        res.status(500).json({ message: "Gagal mengambil detail.", error: error.message });
    }
};

// UPDATE 
exports.updateSimultaneousData = async (req, res) => {
    const { id_master } = req.params;
    const { nim, nama_lengkap, status_aktif_asdos, kode_mk, nama_mk, sks, nip_nik, nama_dosen, jabatan } = req.body;

    try {
        const queries = [
            { 
                sql: 'UPDATE asisten_dosen SET nim=?, nama_lengkap=?, status_aktif_asdos=? WHERE id_master=?', 
                values: [nim, nama_lengkap, status_aktif_asdos, id_master] 
            },
            { 
                sql: 'UPDATE mata_kuliah SET kode_mk=?, nama_mk=?, sks=? WHERE id_master=?', 
                values: [kode_mk, nama_mk, sks, id_master] 
            },
            { 
                sql: 'UPDATE dosen_koordinator SET nip_nik=?, nama_dosen=?, jabatan=? WHERE id_master=?', 
                values: [nip_nik, nama_dosen, jabatan, id_master] 
            }
        ];

        await executeTransaction(queries);
        res.status(200).json({ message: "Data berhasil diperbarui." });
    } catch (error) {
        res.status(500).json({ message: "Gagal update data.", error: error.message });
    }
};