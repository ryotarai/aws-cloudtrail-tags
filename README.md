## Deploy

```
cp sam.example.yaml sam.yaml
vim sam.yaml

cp config.example.py config.py
vim config.py
```

```
S3_BUCKET_NAME=your-s3-bucket-name
sam package \
   --template-file sam.yaml \
   --output-template-file sam-output.yaml \
   --s3-bucket "$S3_BUCKET_NAME" \
   --s3-prefix sam/aws-tags-by-cloudtrail
sam deploy \
   --template-file sam-output.yaml \
   --stack-name aws-tags-by-cloudtrail \
   --capabilities CAPABILITY_IAM
```
