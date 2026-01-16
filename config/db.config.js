
const mysql = require('mysql2/promise');
const dbConfig = {
    host: 'localhost', 
    user: 'root', 
    password: 'ZaZaR!CH1', 
    database: 'simados_tu_db', 
    port: 3308,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};
const pool = mysql.createPool(dbConfig);

module.exports = pool;