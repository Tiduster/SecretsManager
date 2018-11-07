# SecretsManager
AWS Secrets Manager Python Interface

# Requirements

```
pip3 install boto3 jinja2
```

# Usage

```
python3 secrets_manager.py
usage: secrets_manager.py [-h] [--verbosity {INFO,ERROR,DEBUG}]
                          {get,set,list,delete,find}

secrets_manager.py get
  secret_name           The secret to get or set
  --create              Create secret if necessary
  --silent              Disable secret display
  --template [TEMPLATE_FILES [TEMPLATE_FILES ...]]
                        template_path output_file
  --tags KEY1=VAL1,KEY2=VAL2...
                        Add tags to the secret
  --secret_length SECRET_LENGTH
                        Secret string length
  --exclude_punctuation
                        Exclude punctuation from secret

secrets_manager.py set
  get with --create by default

secrets_manager.py delete
  secret_name     The secret to delete
  --delay [7-30]  Recovery window, between 7 and 30 days
  --force         Disable recovery window

secrets_manager.py list

secrets_manager.py find
  --secret_name SECRET_NAME
                        The secret to return
  --tags KEY1=VAL1,KEY2=VAL2...
                        Find secrets using these tags
```

# Examples

```
python3 secrets_manager.py get secret0 --template templates/secretsManager.j2 templates/config.ini
python3 secrets_manager.py set secret3 --exclude_punctuation
python3 secrets_manager.py set secret4 --secret_length 16 --tags key1=value1,key3=value2
python3 secrets_manager.py delete secret3 --force
python3 secrets_manager.py delete secret4 --delay 14
python3 secrets_manager.py find --secret_name secret0
python3 secrets_manager.py find --tags key3=value2,key1=value1
```

# Docker

## Docker build

```
docker build -t aws_secrets_manager:0.x .
```

## Docker run

```
docker run -ti -v ~/.aws:/root/.aws/ -v ~/templates:/root/templates -e AWS_PROFILE=ADMIN aws_secrets_manager:0.x list
docker run -ti -v ~/.aws:/root/.aws/ -v ~/templates:/root/templates -e AWS_PROFILE=ADMIN aws_secrets_manager:0.x get mysecret1 --create --template /root/templates/secretsManager.j2 /root/templates/config.ini
```
