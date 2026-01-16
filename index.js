require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const masterRoutes = require('./routes/master.routes');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
    res.json({ message: "Welcome to SIMADOS-TU Backend API." });
});

app.use('/api', masterRoutes);

const pool = require('./config/db.config'); // Pastikan pool diimpor

pool.getConnection()
    .then(connection => {
        console.log("Database connection successful!");
        connection.release();
    })
    .catch(err => {
        console.error("Database connection failed:", err.message);
    });

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}.`);
});