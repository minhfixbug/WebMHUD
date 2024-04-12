<?php
header('Access-Control-Allow-Origin: *');
// Thiết lập header cho phản hồi kiểu JSON
header('Content-Type: application/json');
// Đọc và trả về nội dung của file token.json
echo file_get_contents('token.json');
?>