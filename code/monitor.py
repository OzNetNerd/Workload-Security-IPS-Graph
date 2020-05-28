import os
import sys
import warnings
import deepsecurity as api
from deepsecurity.rest import ApiException
import boto3

if not sys.warnoptions:
    warnings.simplefilter('ignore')

API_ADDR = 'https://app.deepsecurity.trendmicro.com/api'

class Ws:
    def __init__(self):

        try:
            ws_api_key = os.environ['WS_KEY']
            self.api_version = os.environ.get('WS_API_VERSION', 'v1')

        except KeyError:
            sys.exit('"WS_KEY" environment variables are not set. Please set them and try again.')

        config = api.Configuration()
        config.host = API_ADDR
        config.api_key['api-secret-key'] = ws_api_key

        self.api_client = api.ApiClient(config)
        self.cw_client = boto3.client('cloudwatch')

    def get_computers(self):
        expand = api.Expand(api.Expand.intrusion_prevention)

        try:
            computers_api = api.ComputersApi(self.api_client)
            computer_list = computers_api.list_computers(self.api_version, expand=expand.list(), overrides=False)

        except ApiException as e:
            return 'Exception: ' + str(e)

        computers = dict()

        for computer in computer_list.computers:
            computers[computer.host_name] = computer

        return computers

    def get_metrics(self):
        metric_name = 'AppliedIpsRules'
        unit = 'Count'
        computers = self.get_computers()
        entries = []

        for hostname, data in computers.items():
            status_msg = data.intrusion_prevention.module_status.agent_status_message

            if 'On' not in status_msg:
                continue

            num_applied_rules = int(status_msg.split(' ')[2])
            platform = data.platform

            entry = {
                'MetricName': metric_name,
                'Dimensions': [
                    {
                        'Name': 'Hostname',
                        'Value': hostname,
                    },
                    {
                        'Name': 'Platform',
                        'Value': platform,
                    },
                ],
                'Unit': unit,
                'Value': num_applied_rules,
            }

            entries.append(entry)

        return entries

    def send_metrics(self, entries, namespace='cloudone/workloadsecurity'):
        self.cw_client.put_metric_data(
            MetricData=entries,
            Namespace=namespace,
        )


def main():
    ws = Ws()
    metrics = ws.get_metrics()
    ws.send_metrics(metrics)


if __name__ == '__main__':
    main()
