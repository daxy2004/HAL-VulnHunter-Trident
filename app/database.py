import sqlite3

def init_db():
    # Connect to the SQLite database (or create it if it doesn't exist)
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Read and execute the SQL commands from init_db.sql
    with open('init_db.sql', 'r') as sql_file:
        sql_script = sql_file.read()
    cursor.executescript(sql_script)

    # Commit changes and close the connection
    conn.commit()
    conn.close()
