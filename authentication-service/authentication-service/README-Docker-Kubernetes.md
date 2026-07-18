# Authentication Service Docker and Kubernetes

## Local Docker Compose

Run the authentication service with PostgreSQL, Redis, and Kafka:

```bash
docker compose up --build
```

If your IDE tries to pull `codeforge/authentication-service:local`, run Compose from this directory or use:

```bash
docker compose build authentication-service
docker compose up
```

The API is exposed at:

```text
http://localhost:8082
```

The container still runs on port `8081`; Compose maps it to host port `8082` by default to avoid conflicts with a locally running app. Override it with:

```bash
AUTH_SERVICE_HOST_PORT=8081 docker compose up --build
```

Compose uses the `postgres` Spring profile and these internal service names:

```text
postgres:5432
redis:6379
kafka:9092
```

Stop the stack:

```bash
docker compose down
```

Delete persisted local data:

```bash
docker compose down -v
```

## Kubernetes

Build the image first:

```bash
docker build -t codeforge/authentication-service:local .
```

For Docker Desktop Kubernetes, the local image is usually available directly. For Minikube, build inside Minikube:

```bash
minikube image build -t codeforge/authentication-service:local .
```

Apply manifests:

```bash
kubectl apply -f k8s/
```

Check pods:

```bash
kubectl get pods -n codeforge
```

Access the service:

```bash
kubectl port-forward -n codeforge service/authentication-service 8081:8081
```

Then call:

```text
http://localhost:8081
```

The NodePort is also defined as `30081`, if your Kubernetes environment exposes node ports.

## Production Notes

Change these before using outside local development:

- `AUTH_JWT_SECRET`
- `AUTH_DATASOURCE_PASSWORD`
- Kafka security settings
- Redis password/TLS settings
- image name and registry
- storage classes for the PVCs

The included Kafka setup uses `apache/kafka:3.7.1` in single-node KRaft mode for development. For production, use a managed Kafka service or a proper Kafka operator.
