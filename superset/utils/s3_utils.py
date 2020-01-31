import boto3
from botocore.exceptions import ClientError
import asyncio

def get_file_data(bucket_name, object_name, file_name):
    s3 = boto3.client('s3')
    with open(file_name, 'wb') as f:
        s3.download_fileobj(bucket_name, object_name, f)

def upload_file(bucket_name, file_name, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name
    file_name = 'data_file.json'
    # Upload the file
    s3_client = boto3.client('s3')
    try:
        # s3_client.Object(bucket, object_name + date.today()).copy_from(CopySource=object_name)
        # s3_client.Object(bucket, object_name).delete()
        response = s3_client.upload_file(file_name, bucket_name, object_name)
    except ClientError as e:
        logging.error(e)
        return False
    return None