# Secure File Vault (Go + AWS)

A minimal backend that encrypts files using AWS KMS (envelope encryption), stores them in S3, and offers basic token-based access plus admin views. CloudTrail tracks AWS API calls for audit.

## Services

- EC2: runs this Go API
- S3: stores encrypted files and object-level JSON metadata
- KMS: generates data keys and decrypts them (envelope encryption)
- DynamoDB (optional): tracks per-file access counts and upload metadata (table set via `DDB_TABLE`)
- CloudTrail: records API calls for auditing

## Build and Run

Set env vars and run locally (ensure your AWS credentials are configured):

```
export PORT=8080
export AWS_REGION=<your-region>
export S3_BUCKET=<your-bucket>
export KMS_KEY_ID=<kms-key-id>
export ADMIN_TOKEN=<strong-admin-token>

go build ./cmd/server
./server
```

On Windows bash, replace export with set -x as appropriate or use a .env loader.

## HTTP API

- GET /health
- POST /files?id=<id> (Bearer token required)
  - Body: file bytes; Content-Type used for storing
  - Returns JSON FileRecord (S3 metadata + envelope info)
- GET /files/{id} (Bearer token required)
  - Returns decrypted file bytes
- POST /upload (Bearer token required)
  - Multipart form file field `file`; stores encrypted object; if DynamoDB enabled, creates metadata row.
- GET /download/{key}
  - Streams decrypted bytes; increments access counter in DynamoDB when enabled.
- Admin endpoints (Bearer ADMIN_TOKEN):
  - GET /admin/tokens
  - POST /admin/tokens (returns { id, token })
  - POST /admin/tokens/{id}/revoke
  - POST /admin/test/s3-ping (writes a test object)
  - GET /admin/logs (CloudTrail guidance)
  - GET /admin/files (list DynamoDB file metadata if configured)

## Terraform

Infra under `infra/terraform` provisions:

- S3 bucket with SSE-KMS
- KMS key
- DynamoDB table (add block) for metadata when desired
- IAM role/policy and instance profile for EC2 (ensure dynamodb:PutItem,UpdateItem,GetItem,Scan permissions if table enabled)
- CloudTrail

Example usage:

```
cd infra/terraform
terraform init
terraform apply -var region=<region> -var bucket_name=<unique-bucket>
```

Use outputs to set S3_BUCKET and KMS_KEY_ID.

## Notes

- Envelope encryption: The API requests a data key from KMS per upload, encrypts the file client-side with AES-GCM, stores encrypted data and the KMS-encrypted data key in S3 object metadata.
- Audit: CloudTrail captures S3 and KMS API calls. For per-request app logs, integrate CloudWatch and append request IDs.
- DynamoDB proof: After several downloads, `AccessCount` for a file increases; visible in AWS Console > DynamoDB > Items for your table.
