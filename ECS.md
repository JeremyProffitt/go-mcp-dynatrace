# ECS Deployment Guide for go-mcp-dynatrace

> **LLM Context**: This file documents AWS ECS deployment. When users ask about deploying or hosting the MCP server, reference this guide. Note: All AWS changes must go through GitHub Actions pipelines per CLAUDE.md policy.

This guide covers deploying go-mcp-dynatrace as an HTTP service on AWS ECS (Elastic Container Service) using either Fargate or EC2 launch types.

## Architecture Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   MCP Client    │────▶│  Load Balancer  │────▶│   ECS Service   │
│ (Claude Code/   │     │     (ALB)       │     │   (Fargate/EC2) │
│  Continue.dev)  │     └─────────────────┘     └─────────────────┘
└─────────────────┘              │                       │
                                 │                       ▼
                                 │              ┌─────────────────┐
                                 │              │   Dynatrace     │
                                 │              │   Platform API  │
                                 │              └─────────────────┘
                                 ▼
                        ┌─────────────────┐
                        │ Secrets Manager │
                        └─────────────────┘
```

## Prerequisites

1. AWS CLI configured with appropriate permissions
2. Docker installed locally for building images
3. An ECR repository created for the image
4. VPC with subnets configured for ECS
5. Dynatrace credentials (OAuth or Platform Token)

## Quick Start

### 1. Build and Push Docker Image

```bash
# Authenticate to ECR
aws ecr get-login-password --region YOUR_REGION | docker login --username AWS --password-stdin YOUR_ACCOUNT_ID.dkr.ecr.YOUR_REGION.amazonaws.com

# Build the image
docker build -t go-mcp-dynatrace .

# Tag for ECR
docker tag go-mcp-dynatrace:latest YOUR_ACCOUNT_ID.dkr.ecr.YOUR_REGION.amazonaws.com/go-mcp-dynatrace:latest

# Push to ECR
docker push YOUR_ACCOUNT_ID.dkr.ecr.YOUR_REGION.amazonaws.com/go-mcp-dynatrace:latest
```

### 2. Create Secrets in AWS Secrets Manager

```bash
aws secretsmanager create-secret \
    --name mcp/dynatrace \
    --secret-string '{
        "DT_ENVIRONMENT": "https://abc12345.apps.dynatrace.com",
        "OAUTH_CLIENT_ID": "dt0s02.XXXXXXXX",
        "OAUTH_CLIENT_SECRET": "dt0s02.XXXXXXXX.XXXXXXXXXXXXXXXX",
        "DT_ACCOUNT_URN": "urn:dtaccount:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "MCP_AUTH_TOKEN": "your-secure-auth-token"
    }'
```

### 3. Create IAM Roles

#### Task Execution Role

This role allows ECS to pull images and retrieve secrets:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue"
            ],
            "Resource": "arn:aws:secretsmanager:YOUR_REGION:YOUR_ACCOUNT_ID:secret:mcp/dynatrace*"
        }
    ]
}
```

#### Task Role

This role is used by the running container (minimal permissions needed):

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        }
    ]
}
```

### 4. Create ECS Resources

```bash
# Create CloudWatch Log Group
aws logs create-log-group --log-group-name /ecs/go-mcp-dynatrace

# Register Task Definition
aws ecs register-task-definition --cli-input-json file://ecs-task-definition.json

# Create ECS Cluster (if not exists)
aws ecs create-cluster --cluster-name mcp-servers

# Create Service
aws ecs create-service \
    --cluster mcp-servers \
    --service-name go-mcp-dynatrace \
    --task-definition go-mcp-dynatrace \
    --desired-count 1 \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}"
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DT_ENVIRONMENT` | Yes | Dynatrace environment URL |
| `OAUTH_CLIENT_ID` | Yes* | OAuth client ID |
| `OAUTH_CLIENT_SECRET` | Yes* | OAuth client secret |
| `DT_ACCOUNT_URN` | Yes* | Account URN for OAuth |
| `DT_PLATFORM_TOKEN` | Yes* | Alternative to OAuth credentials |
| `MCP_AUTH_TOKEN` | No | Token for HTTP authentication |
| `MCP_LOG_LEVEL` | No | Log level (default: info) |

*Either OAuth credentials OR Platform Token required.

### Authentication

When `MCP_AUTH_TOKEN` is set, all HTTP requests to the MCP server must include the `X-MCP-Auth-Token` header with the matching token value.

```bash
# Example request with authentication
curl -X POST http://your-alb-url:3000/ \
    -H "Content-Type: application/json" \
    -H "X-MCP-Auth-Token: your-secure-auth-token" \
    -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

## Security Considerations

1. **Use HTTPS**: Place an Application Load Balancer (ALB) with HTTPS termination in front of the ECS service
2. **Private Subnets**: Deploy ECS tasks in private subnets with NAT Gateway for outbound internet access
3. **Security Groups**: Restrict inbound traffic to only the ALB security group
4. **Secrets Management**: Always use AWS Secrets Manager for sensitive credentials
5. **Authentication**: Enable `MCP_AUTH_TOKEN` for production deployments
6. **VPC Endpoints**: Consider using VPC endpoints for ECR and Secrets Manager to keep traffic private

## Monitoring

### CloudWatch Logs

Logs are automatically sent to CloudWatch Logs at `/ecs/go-mcp-dynatrace`.

### Health Checks

The service exposes a `/health` endpoint that returns:
```json
{"status": "healthy", "server": "Dynatrace MCP Server"}
```

### Metrics

Monitor these CloudWatch metrics for the ECS service:
- `CPUUtilization`
- `MemoryUtilization`
- `RunningTaskCount`

## Scaling

### Auto Scaling

```bash
# Register scalable target
aws application-autoscaling register-scalable-target \
    --service-namespace ecs \
    --resource-id service/mcp-servers/go-mcp-dynatrace \
    --scalable-dimension ecs:service:DesiredCount \
    --min-capacity 1 \
    --max-capacity 10

# Create scaling policy based on CPU
aws application-autoscaling put-scaling-policy \
    --policy-name cpu-scaling \
    --service-namespace ecs \
    --resource-id service/mcp-servers/go-mcp-dynatrace \
    --scalable-dimension ecs:service:DesiredCount \
    --policy-type TargetTrackingScaling \
    --target-tracking-scaling-policy-configuration '{
        "TargetValue": 70.0,
        "PredefinedMetricSpecification": {
            "PredefinedMetricType": "ECSServiceAverageCPUUtilization"
        }
    }'
```

## Troubleshooting

### Common Issues

1. **Task fails to start**: Check CloudWatch logs for startup errors
2. **Health check failures**: Ensure security group allows inbound on port 3000
3. **Secrets not loading**: Verify task execution role has Secrets Manager permissions
4. **Connection to Dynatrace fails**: Check VPC has outbound internet access

### Debugging

```bash
# View task logs
aws logs tail /ecs/go-mcp-dynatrace --follow

# Describe service events
aws ecs describe-services --cluster mcp-servers --services go-mcp-dynatrace

# Check task status
aws ecs list-tasks --cluster mcp-servers --service-name go-mcp-dynatrace
```

## EC2 Launch Type

For EC2 launch type instead of Fargate:

1. Change `requiresCompatibilities` to `["EC2"]` in task definition
2. Remove `cpu` and `memory` from task level (set at container level)
3. Change `networkMode` to `bridge` if not using awsvpc
4. Ensure EC2 instances have the ECS agent installed

See [INTEGRATION.md](./INTEGRATION.md) for configuring Claude Code and Continue.dev to connect to this service.
