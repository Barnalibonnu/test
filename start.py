from improved_scriptV2 import TokenManager, APIClient, WebServer

def create_app():
    # Initialize from environment variables
    token_manager = TokenManager("eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMzg2MjM4ODQsImp0aSI6ImI0ODA0NzEyMmI1YjhlMTc3NmRmOWNhNzcyMTY4MjYwIiwiaWF0IjoxNzQxNDYyMjU4LCJleHAiOjE3NDE1NDg2NTh9.n52pWbrd_Hbx1PXeTMMVol_x03odTH4LxmRqhW9QMa0", "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMzg2MjM4ODQsInRva2VuIjoiNmEyMzcxMWJkZGRjM2IwZjVlM2FjYzRjZjNhMjZlYTgiLCJpYXQiOjE3NDE0NjIyNTgsImV4cCI6MTc0NDE0MDY1OH0.S3NoiT8ZJiRlMxT85NQLs71rxjtnCVO069uuZYJk8Ek")
    api_client = APIClient(token_manager)
    server = WebServer(api_client)
    return server.setup_flask_server()

app = create_app()
