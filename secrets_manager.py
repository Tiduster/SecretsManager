#!/usr/bin/env python3

#TODO: KmsKeyId !
#TODO: Region selection ?
#TODO: VersionID / VersionStage ?
#TODO: SecretBinary

# pylint: disable=not-callable

import os
import sys
import json
import argparse
import logging
import logging.config
import boto3
from botocore.exceptions import ClientError
from jinja2 import Environment, FileSystemLoader

class SecretNotFound(Exception):
    pass

class SecretAwaitingDeletion(Exception):
    pass

class UnknownError(Exception):
    pass

class ExpiredTokenException(Exception):
    pass

# @StackOverflow 29986185
class StoreDictKeyPair(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        my_dict = {}
        try:
            for kv in values.split(","):
                k, v = kv.split("=")
                my_dict[k] = v
            setattr(namespace, self.dest, my_dict)
        except ValueError:
            logging.error("Incorrect syntax, please verify your tags")
            sys.exit(3)

def list_secrets():
    client = boto3.client('secretsmanager')
    secrets = client.list_secrets()
    for secret in secrets['SecretList']:
        if 'Tags' in secret:
            logging.info("%s %s", secret['Name'], secret['Tags'])
        else:
            logging.info(secret['Name'])

def delete_secret(args):
    client = boto3.client('secretsmanager')
    if args.force:
        # Remove secret immediately
        client.delete_secret(SecretId=args.secret_name, ForceDeleteWithoutRecovery=True)
    else:
        # Remove secret in x Days
        client.delete_secret(SecretId=args.secret_name, RecoveryWindowInDays=args.delay)
    logging.info("Secret '%s' deleted", args.secret_name)

def find_secret(args):
    client = boto3.client('secretsmanager')
    if args.secret_name:  # Find secret by name
        secret = client.describe_secret(SecretId=args.secret_name)
        if 'Tags' in secret:
            logging.info("%s %s", secret['Name'], secret['Tags'])
        else:
            logging.info(secret['Name'])
    else:  # Find secret using tags
        secrets = client.list_secrets()  # Return all secrets
        for secret in secrets['SecretList']:
            if 'Tags' in secret:  # If the secret has tags
                for tag in secret['Tags']:
                    for k, v in args.tags.items():
                        if tag['Key'] == k and tag['Value'] == v:  # If tags match user search
                            logging.info("%s %s", secret['Name'], secret['Tags'])

def get_set_secret(args):
    secret_name = args.secret_name
    template_files = args.template_files

    client = boto3.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logging.debug("Secret '%s' not found", secret_name)

            if(args.allow_creation):
                logging.debug("Creation of secret '%s'", secret_name)

                # Call AWS function 'get_random_password'
                generated_secret = client.get_random_password(
                    PasswordLength=args.secret_length,
                    ExcludePunctuation=args.exclude_punctuation,
                    RequireEachIncludedType=True
                )
                logging.debug("%s", generated_secret)

                if isinstance(args.tags, dict):  # If user specified some tags
                    aws_tags = []
                    for k, v in args.tags.items():
                        aws_tags.append({'Key': k, 'Value': v})
                    response = client.create_secret(Name=secret_name, SecretString=generated_secret['RandomPassword'], Tags=aws_tags)
                else:
                    response = client.create_secret(Name=secret_name, SecretString=generated_secret['RandomPassword'])
            else:
                # No secret and --create wasn't specified
                raise SecretNotFound("Secrets Manager can't find the specified secret '%s'", secret_name)

        elif e.response['Error']['Code'] == 'InvalidRequestException' and 'it was deleted' in e.response['Error']['Message']:
            raise SecretAwaitingDeletion("This secret is awaiting deletion")
        elif e.response['Error']['Code'] == 'ExpiredTokenException':
            raise ExpiredTokenException("Please renew your AWS Token")
        else:
            raise UnknownError("Unknown Error : %s", json.dumps(e.response))

    logging.debug("%s", response)
    if 'SecretString' in response:
        plain_text_secret = response['SecretString']  # GET
    else:
        plain_text_secret = generated_secret['RandomPassword']  # SET
    logging.info("%s", plain_text_secret)

    # If user ask for template generation
    if template_files:
        file_loader = FileSystemLoader(os.path.dirname(template_files[0]))
        env = Environment(loader=file_loader)
        template = env.get_template(os.path.basename(template_files[0]))
        output = template.render(secret=plain_text_secret)
        with open(template_files[1], 'w') as stream:
            stream.write(output)
            stream.write('\n')

def main():
    parser = argparse.ArgumentParser()
    verbosity_choices = ['INFO', 'ERROR', 'DEBUG']
    parser.add_argument('--verbosity', choices=verbosity_choices, type=str, default='INFO')
    subparsers = parser.add_subparsers(dest='subcommand')
    subparsers.required = True

    parser_get = subparsers.add_parser('get', aliases=['set'])
    parser_get.add_argument('secret_name', help="The secret to get or set")
    parser_get.add_argument('--create', dest='allow_creation', action='store_true', help="Create secret if necessary")
    parser_get.add_argument('--silent', dest='no_stdout', action='store_true', help="Disable secret display")
    parser_get.add_argument('--template', dest='template_files', nargs='*', default=False, help="template_path output_file")
    parser_get.add_argument('--tags', action=StoreDictKeyPair, default=None,
                            metavar="KEY1=VAL1,KEY2=VAL2...", help="Add tags to the secret")
    parser_get.add_argument('--secret_length', type=int, default=32, help="Secret string length")
    parser_get.add_argument('--exclude_punctuation', action='store_true', help="Exclude punctuation from secret")
    parser_get.set_defaults(func=get_set_secret)

    parser_list = subparsers.add_parser('list')
    parser_list.set_defaults(func=list_secrets)

    parser_delete = subparsers.add_parser('delete')
    parser_delete.add_argument('secret_name', help="The secret to delete")
    parser_delete.add_argument('--delay', type=int, default=30, metavar="[7-30]", help="Recovery window, between 7 and 30 days")
    parser_delete.add_argument('--force', action='store_true', help="Disable recovery window")
    parser_delete.set_defaults(func=delete_secret)

    parser_find = subparsers.add_parser('find')
    parser_find.add_argument('--secret_name', default=None, help="The secret to return")
    parser_find.add_argument('--tags', action=StoreDictKeyPair, default=None,
                             metavar="KEY1=VAL1,KEY2=VAL2...", help="Find secrets using these tags")
    parser_find.set_defaults(func=find_secret)

    args = parser.parse_args()

    if args.subcommand == 'get' or args.subcommand == 'set':
        if args.template_files:
            if len(args.template_files) != 2:
                parser.error("--template require template_path and output_file")
            args.no_stdout = True  # Disable stdout for template generation
        if args.no_stdout and args.verbosity != 'DEBUG':
            args.verbosity = 'ERROR'
    if args.subcommand == 'set':
        args.allow_creation = True  # With 'set' allow secret creation by default

    if args.subcommand == 'delete':
        if args.delay < 7 or args.delay > 30:
            parser.error("Recovery windows must be between 7 and 30 days")

    if args.subcommand == 'find':
        if args.secret_name is None and args.tags is None:
            parser.error("You need to specify a secret_name or some tags")

    # Configure verbosity and redirect error logging to stderr
    logging.config.dictConfig({
        "version": 1,
        "handlers": {
            "console": {
                "level": args.verbosity,
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            },
        },
        "root": {
            "level": args.verbosity,
            "handlers": ["console"],
        },
    })

    try:
        if args.subcommand == 'list':
            args.func()
        else:
            args.func(args)
    except Exception as e: # pylint: disable=broad-except
        if args.verbosity == 'DEBUG':
            logging.error("%s", e, exc_info=True)
        else:
            logging.error("%s %s", type(e), e)
        sys.exit(1)

if __name__ == '__main__':
    main()
