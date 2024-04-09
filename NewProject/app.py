import pyodbc

server = 'MSI'
database = 'MHUD'
connection_string = f"DRIVER=ODBC Driver 17 for SQL Server;SERVER=MSI;DATABASE=MHUD;Trusted_Connection=yes;TrustServerCertificate=yes;"

try:
    conn = pyodbc.connect(connection_string)
    print("Ket noi thanh cong!")
    conn.close()
except Exception as e:
    print("Loi khi ket noi den may chu SQL Server:", str(e).encode('ascii', 'ignore').decode('ascii'))
