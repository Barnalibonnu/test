# Add this at the end of your script
if __name__ == "__main__":
    import os
    # Create token manager and API client
    token_manager = TokenManager(
        access_token="eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMzg2MjM4ODQsImp0aSI6ImI0ODA0NzEyMmI1YjhlMTc3NmRmOWNhNzcyMTY4MjYwIiwiaWF0IjoxNzQxNDYyMjU4LCJleHAiOjE3NDE1NDg2NTh9.n52pWbrd_Hbx1PXeTMMVol_x03odTH4LxmRqhW9QMa0", 
        refresh_token="eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMzg2MjM4ODQsInRva2VuIjoiNmEyMzcxMWJkZGRjM2IwZjVlM2FjYzRjZjNhMjZlYTgiLCJpYXQiOjE3NDE0NjIyNTgsImV4cCI6MTc0NDE0MDY1OH0.S3NoiT8ZJiRlMxT85NQLs71rxjtnCVO069uuZYJk8Ek"
    )
    api_client = APIClient(token_manager)
    
    # Set up the web server
    server = WebServer(api_client)
    app = server.setup_flask_server()
    
    # Start the server
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
else:
    # For Gunicorn
    token_manager = TokenManager(
        access_token="YOUR_ACCESS_TOKEN_HERE", 
        refresh_token="YOUR_REFRESH_TOKEN_HERE"
    )
    api_client = APIClient(token_manager)
    server = WebServer(api_client)
    app = server.setup_flask_server()
