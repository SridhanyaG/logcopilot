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
- `POST /v1/logs/langgraph` - Natural language log analysis

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

```bash
curl "http://localhost:8000/v1/logs/exceptions?hours=8"
```

### Natural Language Log Analysis

```bash
curl -X POST http://localhost:8000/v1/logs/langgraph \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What errors occurred in the last 8 hours?",
    "timeframe": {"hours": 8}
  }'
```

## CloudWatch Integration

The application queries CloudWatch Logs Insights with the following query:

```
fields @timestamp, @message, @logStream, @log
| sort @timestamp desc
| limit 10000
```

This matches the query from your CloudWatch console for the `/ecs/crocin-backend` log group.

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

