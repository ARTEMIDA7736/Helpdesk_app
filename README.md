# HelpDesk FastAPI App (example)

This small application implements a HelpDesk backend with:
- SQLAlchemy models: User, Ticket, Category, Status, Priority, Comment
- JWT-based authentication (token endpoint at `/token`)
- Endpoints:
  - `POST /signup` – register a user. Returns 201.
  - `POST /token` – login (form data: username=email, password). Returns JWT token.
  - `GET /users` – list users (requires auth).
  - `GET /tickets` – list tickets (requires auth).
  - `POST /tickets` – create ticket (requires auth).
  - `GET /tickets/{id}` – get ticket by id (requires auth).
  - `PUT /tickets/{id}` – update ticket (requires auth; creator/agent/admin).
  - `DELETE /tickets/{id}` – delete ticket (requires auth; creator/admin).
  - `POST /tickets/{id}/comments` – add comment to ticket (requires auth).

Response codes used: 200, 201, 400, 401, 404, 500 where appropriate.

## Run locally

1. Create virtual env and install requirements:
```
pip install -r requirements.txt
```
2. Run server:
```
uvicorn main:app --reload
```
3. Open docs: http://127.0.0.1:8000/docs

## Notes
- This is a small demo; in production change SECRET_KEY, use migrations, improve error handling and permissions.
- The DB is SQLite file `helpdesk.db` created in the working directory.