
FROM python:3.8-slim

WORKDIR /app
RUN pip install cryptography==36.0.2
RUN pip install Flask Flask-Admin Flask-Migrate Flask-SQLAlchemy PyCryptodome PyOpenSSL==24.0.0 gunicorn
COPY . .

CMD ["gunicorn", "-b", "0.0.0.0:8000", "main:create_app()"]
