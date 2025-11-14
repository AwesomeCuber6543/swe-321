# Backend API

This is the FastAPI backend for the project.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Make sure your `project.env` file is configured in the project root.

## Running the Backend

From the **backend directory**, run:

```bash
cd backend
./start.sh
```

Or directly with uvicorn from the backend directory:

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8001
```

The API will be available at `http://localhost:8001`

## API Documentation

Once running, visit:
- Swagger UI: `http://localhost:8001/docs`
- ReDoc: `http://localhost:8001/redoc`

## Project Structure

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI app and endpoints
│   ├── auth.py          # Authentication logic
│   ├── settings.py      # Settings loader
│   └── database.py      # Database connection and tables
├── schemas/
│   ├── __init__.py
│   ├── models.py        # Pydantic models
│   ├── settings.py      # Settings schema
│   └── auth.py          # Auth-related models
└── start.sh             # Startup script
```

