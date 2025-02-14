from app import create_app,create_admin_user

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
    # create_admin_user(app)
