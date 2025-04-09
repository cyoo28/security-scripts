import base64
import gzip
import json
from io import BytesIO

def lambda_handler(event, context):
    # Decode the base64-encoded log data
    compressed_data = base64.b64decode(event['awslogs']['data'])
    # Decompress the gzip-compressed data
    with gzip.GzipFile(fileobj=BytesIO(compressed_data), mode='rb') as f:
        json_data = json.loads(f.read().decode('utf-8'))
    
    # Extract the log events (messages from CloudWatch Logs)
    log_events = json_data['logEvents']
    # Return the log events as a response (or simply the first log event for example)
    return {
        'statusCode': 200,
        'body': json.dumps(log_events)  # You can return all events or filter as needed
    }
