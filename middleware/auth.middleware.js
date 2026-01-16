const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET; 

exports.verifyToken = (req, res, next) => { 
    const authHeader = req.headers.authorization;
    const token = authHeader ? authHeader.split(' ')[1] : null;

    if (!token) {
        return res.status(403).json({ 
            message: 'Akses ditolak. Token tidak disediakan.' 
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        req.user = decoded; 
        
        next(); 
    } catch (error) {
        return res.status(401).json({ 
            message: 'Token tidak valid atau telah kedaluwarsa.' 
        });
    }
};