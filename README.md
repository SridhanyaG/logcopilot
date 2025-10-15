# LogCopilot - Log Analytics Dashboard

A FastAPI-based log analytics dashboard with vulnerability scanning and AI-powered insights.

## Features

- **Vulnerability Analysis**: Retrieve critical and high vulnerabilities from ECR image scans
- **AI-Powered Remediation**: Get LLM suggestions for vulnerability fixes
- **Exception Monitoring**: Extract and analyze exceptions from CloudWatch logs
- **Natural Language Queries**: Ask questions about your logs using LangGraph

## API Endpoints

### Vulnerabilities

- `GET /v1/vulnerabilities` - List critical/high vulnerabilities
- `POST /v1/vulnerabilities/suggest` - Get AI remediation suggestions

### Logs

- `GET /v1/logs/exceptions` - Retrieve exceptions from CloudWatch logs
  - Parameters: `hours`, `minutes`, `start_time`, `end_time`, `podname`
  - Supports IST timezone and workload filtering
- `POST /v1/logs/nlp` - Natural language log analysis
  - Parameters: `query`, `timeframe`, `start_time`, `end_time`, `podname`
  - Supports IST timezone and workload filtering

## Setup

1. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment**:

   ```bash
   cp .env.example .env
   # Edit .env with your AWS and OpenAI credentials
   ```

3. **Set up AWS credentials**:

   - Ensure AWS CLI is configured with appropriate permissions
   - Required permissions: ECR, CloudWatch Logs

4. **Run the application**:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

## Configuration

### Environment Variables (.env)

- `AWS_REGION`: AWS region (default: us-east-1)
- `LOG_GROUP_NAME`: CloudWatch log group (default: /ecs/crocin-backend)
- `ECR_REPOSITORY`: ECR repository name
- `ECR_IMAGE_TAG` or `ECR_IMAGE_DIGEST`: Image identifier
- `GITHUB_REPO`: GitHub repository (owner/repo)
- `GITHUB_BRANCH`: Git branch
- `RELEASE_VERSION`: Release version
- `REQUIREMENTS_PATH`: Path to requirements.txt
- `OPENAI_API_KEY`: OpenAI API key
- `OPENAI_MODEL`: OpenAI model (default: gpt-4o-mini)

### Project Configuration (config.yaml)

Contains project-specific settings like repository details, timeframes, and file paths.

## Usage Examples

### Get Vulnerabilities

```bash
curl http://localhost:8000/v1/vulnerabilities
```

### Get Remediation Suggestions

```bash
curl -X POST http://localhost:8000/v1/vulnerabilities/suggest \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CVE-2023-1234",
    "severity": "HIGH",
    "package_name": "requests",
    "package_version": "2.25.1"
  }'
```

### Get Exceptions

#### Basic Time-based Queries

```bash
# Get exceptions from last 1 hour
curl "http://localhost:8000/v1/logs/exceptions?hours=1"

# Get exceptions from last 30 minutes
curl "http://localhost:8000/v1/logs/exceptions?minutes=30"

# Get exceptions from last 24 hours
curl "http://localhost:8000/v1/logs/exceptions?hours=24"
```

#### Custom DateTime Range Queries

```bash
# Get exceptions for specific date range (IST timezone)
curl "http://localhost:8000/v1/logs/exceptions?start_time=2025-10-14T17:00:00&end_time=2025-10-14T19:00:00"

# Get exceptions for a specific day (IST timezone)
curl "http://localhost:8000/v1/logs/exceptions?start_time=2025-10-14T00:00:00&end_time=2025-10-14T23:59:59"

# Get exceptions for last 2 hours using datetime range
curl "http://localhost:8000/v1/logs/exceptions?start_time=2025-10-14T22:00:00&end_time=2025-10-15T00:00:00"
```

#### Filter by Workload/Pod Name

```bash
# Get exceptions from specific workload (crocin-backend)
curl "http://localhost:8000/v1/logs/exceptions?hours=8&podname=crocin-backend"

# Get exceptions from specific workload with custom time range
curl "http://localhost:8000/v1/logs/exceptions?start_time=2025-10-14T17:00:00&end_time=2025-10-14T19:00:00&podname=crocin-backend"

# Get exceptions from specific ECS service
curl "http://localhost:8000/v1/logs/exceptions?hours=4&podname=crocin-backend-service"
```

#### Advanced Examples

```bash
# Get exceptions from last 5 hours with workload filter
curl "http://localhost:8000/v1/logs/exceptions?hours=5&podname=crocin-backend"

# Get exceptions for specific time window (IST timezone)
curl "http://localhost:8000/v1/logs/exceptions?start_time=2025-10-14T18:00:00&end_time=2025-10-14T20:00:00"

# Get exceptions for multiple days
curl "http://localhost:8000/v1/logs/exceptions?start_time=2025-10-13T00:00:00&end_time=2025-10-15T23:59:59"
```

#### Response Format

The endpoint returns:

```json
{
  "count": 47,
  "exceptions": [
    {
      "timestamp": "2025-10-14T18:28:54.034000",
      "message": "ERROR - Error executing LLM-generated Cypher query",
      "log_stream": "ecs/crocin-backend/0da767283d45490d8efe37ed1d97634b",
      "log_group": "058264144445:/ecs/crocin-backend"
    }
  ],
  "summary": "## Overall Summary\nAI-generated markdown summary of exceptions..."
}
```

### Natural Language Log Analysis

#### Basic NLP Queries

```bash
# Ask questions about logs in the last 8 hours
curl -X POST http://localhost:8000/v1/logs/nlp \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What errors occurred in the last 8 hours?",
    "timeframe": {"hours": 8}
  }'

# Ask questions about logs in the last 30 minutes
curl -X POST http://localhost:8000/v1/logs/nlp \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What are the most common errors?",
    "timeframe": {"minutes": 30}
  }'
```

#### Custom DateTime Range NLP Queries

```bash
# Ask questions about specific time range (IST timezone)
curl -X POST http://localhost:8000/v1/logs/nlp \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What errors occurred between 5 PM and 7 PM?",
    "start_time": "2025-10-14T17:00:00",
    "end_time": "2025-10-14T19:00:00"
  }'

# Ask questions about a specific day
curl -X POST http://localhost:8000/v1/logs/nlp \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What was the system performance like today?",
    "start_time": "2025-10-14T00:00:00",
    "end_time": "2025-10-14T23:59:59"
  }'
```

#### NLP Queries with Workload Filtering

```bash
# Ask questions about specific workload
curl -X POST http://localhost:8000/v1/logs/nlp \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What errors occurred in crocin-backend?",
    "timeframe": {"hours": 24},
    "podname": "crocin-backend"
  }'

# Ask questions about specific ECS service with custom time range
curl -X POST http://localhost:8000/v1/logs/nlp \
  -H "Content-Type: application/json" \
  -d '{
    "query": "How is the crocin-backend-service performing?",
    "start_time": "2025-10-14T17:00:00",
    "end_time": "2025-10-14T19:00:00",
    "podname": "crocin-backend-service"
  }'
```

#### Advanced NLP Examples

```bash
# Complex analysis with multiple parameters
curl -X POST http://localhost:8000/v1/logs/nlp \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Analyze the performance issues and provide recommendations",
    "start_time": "2025-10-14T18:00:00",
    "end_time": "2025-10-14T20:00:00",
    "podname": "crocin-backend"
  }'

# Ask about specific error patterns
curl -X POST http://localhost:8000/v1/logs/nlp \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What are the root causes of 500 errors?",
    "timeframe": {"hours": 12}
  }'
```

#### Response Format

The NLP endpoint returns:

```json
{
  "answer": "## Overall Summary\nAI-generated analysis in markdown format...",
  "used_logs": 707
}
```

## CloudWatch Integration

The application queries CloudWatch Logs Insights with the following query:

```
fields @timestamp, @message, @logStream, @log
| sort @timestamp desc
| limit 10000
```

This matches the query from your CloudWatch console for the `/ecs/crocin-backend` log group.

### Timezone Handling

- **Input**: All datetime parameters accept IST (Indian Standard Time) format
- **Processing**: IST times are automatically converted to UTC for CloudWatch queries
- **Format**: Use ISO format without timezone (e.g., `2025-10-14T17:00:00`)
- **Default**: If no timezone is specified, IST (UTC+5:30) is assumed

### Workload Filtering

- **Kubernetes**: Uses `@entity.Attributes.K8s.Workload = 'workload-name'`
- **ECS**: Uses `@logStream like /service-name/` for ECS services
- **Parameter**: `podname` parameter accepts both Kubernetes workload names and ECS service names

## Development

- FastAPI with automatic OpenAPI documentation at `/docs`
- Pydantic models for request/response validation
- AWS SDK integration for ECR and CloudWatch
- OpenAI integration for AI-powered insights
- LangGraph for natural language processing

## Sample Payload

- get
  curl -X 'GET' \
   'http://0.0.0.0:8000/v1/vulnerabilities/' \
   -H 'accept: application/json'
- suggest

curl -X 'POST' \
 'http://0.0.0.0:8000/v1/vulnerabilities/suggest' \
 -H 'accept: application/json' \
 -H 'Content-Type: application/json' \
 -d '{
"name": "CVE-2025-9230",
"severity": "HIGH",
"description": "Issue summary: An application trying to decrypt CMS messages encrypted using password based encryption can trigger an out-of-bounds read and write.",
"package_name": "openssl",
"package_version": "3.5.1-1"}'

- exception /v1/logs/exceptions
  curl -X 'GET' \
   'http://0.0.0.0:8000/v1/logs/exceptions?hours=1' \
   -H 'accept: application/json'

curl -X POST "http://0.0.0.0:8000/v1/logs/nlp" \
 -H "Content-Type: application/json" \
 -d '{"query": "What errors occurred in the last 8 hours?", "timeframe": {"hours": 8}}'

# Test exceptions endpoint (working!)

curl "http://0.0.0.0:8000/v1/logs/exceptions?hours=8" | jq '.count'

# Get just the count

curl "http://0.0.0.0:8000/v1/logs/exceptions?hours=8" | jq '.count'
