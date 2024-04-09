import pyodbc
import cgi
# form = cgi.FieldStorage()
# username = form.getvalue('user')
# email = form.getvalue('email')
# password = form.getvalue('pass')

# print(username)
# print(email)
# print(password)

server = 'MSI'
database = 'MHUD'
connection_string = f"DRIVER=ODBC Driver 17 for SQL Server;SERVER=MSI;DATABASE=MHUD;Trusted_Connection=yes;TrustServerCertificate=yes;"

try:
    conn = pyodbc.connect(connection_string)
    cursor = conn.cursor()

    # Xử lý dữ liệu từ form đăng kí
    form = cgi.FieldStorage()
    username = form.getvalue('user')
    email = form.getvalue('email')
    password = form.getvalue('pass')

    print(username)
    print(email)
    print(password)
    
    cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?)', (username, email, password))
    conn.commit()
    print("Ket noi thanh cong!")
    conn.close()
    print("Location: Userpage.html\r\n\r\n")
except Exception as e:
    print("Loi khi ket noi server!", str(e))

