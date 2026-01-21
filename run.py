from server import create_app,db
from server.models import User

app = create_app()


if __name__ == "__main__":
    app.run(debug=True)