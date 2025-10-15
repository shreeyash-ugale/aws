package awsx

import (
    "context"

    awsconfig "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/dynamodb"
    "github.com/aws/aws-sdk-go-v2/service/kms"
    "github.com/aws/aws-sdk-go-v2/service/s3"
)

type Clients struct {
    S3  *s3.Client
    KMS *kms.Client
    DDB *dynamodb.Client
}

func New(region string) (*Clients, error) {
    cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(region))
    if err != nil {
        return nil, err
    }
    return &Clients{
        S3:  s3.NewFromConfig(cfg),
        KMS: kms.NewFromConfig(cfg),
        DDB: dynamodb.NewFromConfig(cfg),
    }, nil
}
