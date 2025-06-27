# code: language=Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY app.py /app
RUN pip install --no-cache-dir flask gunicorn requests
ENV \
  SSC_URL=https://ssc.example.com \
  SSC_TOKEN=your_ssc_token \
  DTRACK_URL=https://dtrack.example.com \
  DTRACK_TOKEN=your_dtrack_token
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "-w", "4", "app:app"]