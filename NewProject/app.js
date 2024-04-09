const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');

const app = express();

// Kết nối đến cơ sở dữ liệu MySQL
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'MSI',
    password: '',
    database: 'MHUD'
});

connection.connect();

// Middleware để xử lý dữ liệu từ form
app.use(bodyParser.urlencoded({ extended: true }));

// Route xử lý yêu cầu đăng nhập
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    // Truy vấn cơ sở dữ liệu để kiểm tra thông tin đăng nhập
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    connection.query(sql, (err, result) => {
        if (err) throw err;
        if (result.length > 0) {
            // Đăng nhập thành công
            res.send('Login successful!');
        } else {
            // Sai thông tin đăng nhập
            res.send('Incorrect username or password!');
        }
    });
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
