import boto3
from datetime import datetime

def lambda_handler(event, context):
    client = boto3.client('logs', region_name='us-east-1')

    timeFormat = "%Y-%m-%dT%H:%M:%S.%f%z"
    alarmTime = event['time']
    alarmTime = datetime.strptime(alarmTime, timeFormat).timestamp()
    startTime = int((alarmTime - 300)*1000)
    endTime = int((alarmTime + 300)*1000)

    logGroup = "/aws/lambda/Sym-SecOps-GCP-Breakglass"
    filterPattern = "JiraError"

    try:
        response = client.filter_log_events(
            logGroupName=logGroup,
            filterPattern=filterPattern,
            startTime=startTime,
            endTime=endTime
        )
        if response['events']:
            messages = []
            for event in response['events']:
                messages.append(event['message'])
            return messages
        else:
            return ("No log events found for pattern \"{}\" during the time window").format(filterPattern)
    except:
        return ("Error querying log events")
