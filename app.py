from improvedscriptV2.py import TokenManager, APIClient, WebServer

# Initialize from directly specified tokens
token_manager = TokenManager(
    access_token="eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMzg2MjM4ODQsImp0aSI6ImI0ODA0NzEyMmI1YjhlMTc3NmRmOWNhNzcyMTY4MjYwIiwiaWF0IjoxNzQxNDYyMjU4LCJleHAiOjE3NDE1NDg2NTh9.n52pWbrd_Hbx1PXeTMMVol_x03odTH4LxmRqhW9QMa0", 
    refresh_token="eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMzg2MjM4ODQsInRva2VuIjoiNmEyMzcxMWJkZGRjM2IwZjVlM2FjYzRjZjNhMjZlYTgiLCJpYXQiOjE3NDE0NjIyNTgsImV4cCI6MTc0NDE0MDY1OH0.S3NoiT8ZJiRlMxT85NQLs71rxjtnCVO069uuZYJk8Ek"
)
api_client = APIClient(token_manager)
server = WebServer(api_client)
app = server.setup_flask_server()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
