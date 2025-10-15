package metadata

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// FileRecord represents metadata stored per file.
// Partition key: FileID (string)
// Sort key: Type ("file" currently; could be extended for versions)
// Additional GSIs can be added later (e.g., by uploader token).
//
// AccessCount is incremented on each successful download.
// LastAccessUTC updated on each download.
// CreatedUTC set at creation.
// TokenHint stores truncated token hash prefix used at upload for audit linkage (optional).
// SizeBytes of original plaintext content.
// StoredKeyArn references the KMS key used (for demonstrability).
// EncryptedObjectKey is the S3 object key to correlate.
// Bucket is stored for multi-bucket scenarios.
// CipherSuite documents encryption algorithm (AES-256-GCM).
// DataKeyEncryptedLen is length of the encrypted data key for stats.
// NonceLen is length of nonce.
// Tags can hold arbitrary labels.
//
// NOTE: Avoid storing sensitive plaintext; only metadata.
//
// DynamoDB capacity planning: table with PK+SK, on-demand billing initially.
// IAM permissions required: dynamodb:PutItem, UpdateItem, GetItem, Query, Scan.

type FileRecord struct {
	FileID              string   `dynamodbav:"FileID"`
	Type                string   `dynamodbav:"Type"`
	AccessCount         int64    `dynamodbav:"AccessCount"`
	LastAccessUTC       int64    `dynamodbav:"LastAccessUTC"`
	CreatedUTC          int64    `dynamodbav:"CreatedUTC"`
	TokenHint           string   `dynamodbav:"TokenHint"`
	SizeBytes           int64    `dynamodbav:"SizeBytes"`
	StoredKeyArn        string   `dynamodbav:"StoredKeyArn"`
	EncryptedObjectKey  string   `dynamodbav:"EncryptedObjectKey"`
	Bucket              string   `dynamodbav:"Bucket"`
	CipherSuite         string   `dynamodbav:"CipherSuite"`
	DataKeyEncryptedLen int      `dynamodbav:"DataKeyEncryptedLen"`
	NonceLen            int      `dynamodbav:"NonceLen"`
	Tags                []string `dynamodbav:"Tags"`
}

var ErrNotFound = errors.New("record not found")

// Store wraps DynamoDB operations for file metadata.
// Minimal interface abstractions facilitate testing.

type Store struct {
	Table string
	DDB   *dynamodb.Client
}

// NewStore constructs metadata store.
func NewStore(table string, ddb *dynamodb.Client) *Store {
	return &Store{Table: table, DDB: ddb}
}

// PutFileRecord creates a new record; fails if already exists (conditional write).
func (s *Store) PutFileRecord(ctx context.Context, rec *FileRecord) error {
	if rec == nil {
		return errors.New("nil record")
	}
	if rec.FileID == "" {
		return errors.New("empty FileID")
	}
	rec.Type = "file"
	now := time.Now().UTC().Unix()
	rec.CreatedUTC = now
	rec.LastAccessUTC = now
	item, err := attributevalue.MarshalMap(rec)
	if err != nil {
		return err
	}
	_, err = s.DDB.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           &s.Table,
		Item:                item,
		ConditionExpression: awsString("attribute_not_exists(FileID)"),
	})
	return err
}

// IncrementAccess increments AccessCount and updates LastAccessUTC.
func (s *Store) IncrementAccess(ctx context.Context, fileID string) (*FileRecord, error) {
	if fileID == "" {
		return nil, errors.New("empty fileID")
	}
	now := time.Now().UTC().Unix()
	out, err := s.DDB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.Table,
		Key: map[string]types.AttributeValue{
			"FileID": &types.AttributeValueMemberS{Value: fileID},
			"Type":   &types.AttributeValueMemberS{Value: "file"},
		},
		UpdateExpression:          awsString("SET AccessCount = if_not_exists(AccessCount, :zero) + :inc, LastAccessUTC = :ts"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":inc": &types.AttributeValueMemberN{Value: "1"}, ":zero": &types.AttributeValueMemberN{Value: "0"}, ":ts": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now)}},
		ReturnValues:              types.ReturnValueAllNew,
	})
	if err != nil {
		return nil, err
	}
	var rec FileRecord
	if err = attributevalue.UnmarshalMap(out.Attributes, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// GetFileRecord fetches a record by FileID.
func (s *Store) GetFileRecord(ctx context.Context, fileID string) (*FileRecord, error) {
	out, err := s.DDB.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.Table,
		Key: map[string]types.AttributeValue{
			"FileID": &types.AttributeValueMemberS{Value: fileID},
			"Type":   &types.AttributeValueMemberS{Value: "file"},
		},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil || len(out.Item) == 0 {
		return nil, ErrNotFound
	}
	var rec FileRecord
	if err = attributevalue.UnmarshalMap(out.Item, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// ListFiles performs a Scan (acceptable for small demo); for production use GSI and Query patterns.
func (s *Store) ListFiles(ctx context.Context, limit int32) ([]FileRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	out, err := s.DDB.Scan(ctx, &dynamodb.ScanInput{
		TableName: &s.Table,
		Limit:     &limit,
	})
	if err != nil {
		return nil, err
	}
	var list []FileRecord
	if err = attributevalue.UnmarshalListOfMaps(out.Items, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func awsString(s string) *string { return &s }
