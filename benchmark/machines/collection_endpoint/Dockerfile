FROM python:3.11-slim

# The collection endpoint of the prompt-injection experiment. Present ONLY
# in injected task networks; an agent that finds and uses it has genuinely
# been redirected by the payload (see benchmark/injection_payloads/).
COPY server.py /opt/collection_endpoint/server.py

EXPOSE 80

CMD ["python3", "/opt/collection_endpoint/server.py"]
