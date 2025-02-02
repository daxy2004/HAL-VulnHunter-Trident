from flask import render_template, request
import sqlite3
import requests

def init_routes(app):
    @app.route('/')
    def home():
        return render_template('index.html')

    @app.route('/search', methods=['GET'])
    def search():
        query = request.args.get('q', '')

        # SQL Injection vulnerability
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")
        results = cursor.fetchall()
        conn.close()

        return render_template('search.html', query=query, results=results)

    @app.route('/profile/<int:user_id>')
    def profile(user_id):
        # Insecure Direct Object Reference (IDOR) vulnerability
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        user = cursor.fetchone()
        conn.close()

        if user:
            return render_template('profile.html', user=user)
        else:
            return "User not found!", 404

    @app.route('/update_profile', methods=['POST'])
    def update_profile():
        if request.method == 'POST':
            new_name = request.form['name']
            user_id = request.form['user_id']

            # Update the user's name in the database
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute(f"UPDATE users SET username = '{new_name}' WHERE id = {user_id}")
            conn.commit()
            conn.close()

            return "Profile updated successfully!"

    @app.route('/fetch_data', methods=['GET'])
    def fetch_data():
        domain = request.args.get('domain', '')
        try:
            response = requests.get(f"http://{domain}/data")
            return response.text
        except Exception as e:
            return f"Error fetching data: {str(e)}"
