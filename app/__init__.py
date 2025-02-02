from flask import Flask

def create_app():
    app = Flask(__name__)
    app.secret_key = "insecure_secret_key"  # Insecure secret key

    # Import and initialize routes
    from .routes import init_routes
    init_routes(app)

    return app

# Create the app instance
app = create_app()
