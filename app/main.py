from fastapi import FastAPI

app = FastAPI()

@app.post("/")
def hello_world():
    return {"value": "hello_world"}
