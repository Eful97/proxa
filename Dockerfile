# Usa Python 3.11 leggero
FROM python:3.11-slim

# Imposta la directory di lavoro
WORKDIR /app

# Copia e installa le dipendenze
COPY requirements.txt .
# Installiamo anche gunicorn esplicitamente
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn

# Copia tutto il codice
COPY . .

# Render rileva automaticamente la porta, ma impostiamo la 8080 come standard
ENV PORT=8080
EXPOSE 8080

# Comando di avvio per Render
# IMPORTANTE: Assicurati che il file principale si chiami 'app.py' e l'oggetto 'app'.
# Se il file è 'main.py', cambia in "main:app".
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "--worker-class", "aiohttp.worker.GunicornWebWorker", "app:app"]
