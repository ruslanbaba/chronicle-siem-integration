"""
SOAR Integration and Automated Response Handler
"""

import functions_framework
from google.cloud import secretmanager
from google.cloud import pubsub_v1
import requests
import json
import os

# Initialize clients
secret_client = secretmanager.SecretManagerServiceClient()
publisher = pubsub_v1.PublisherClient()

class SOARIntegration:
    def __init__(self):
        self.project_id = os.environ['PROJECT_ID']
        self.soar_api_key = self._get_secret('soar-api-key')
        self.jira_creds = self._get_secret('jira-credentials')
        self.jira_creds_dict = json.loads(self.jira_creds)

    def _get_secret(self, secret_id):
        """Retrieve secret from Secret Manager"""
        name = f"projects/{self.project_id}/secrets/{secret_id}/versions/latest"
        response = secret_client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")

    def create_incident(self, alert_data):
        """Create incident in SOAR platform"""
        headers = {
            'Authorization': f'Bearer {self.soar_api_key}',
            'Content-Type': 'application/json'
        }
        
        incident_data = {
            'title': alert_data['alert_name'],
            'severity': alert_data['severity'],
            'description': alert_data['description'],
            'source': 'Chronicle SIEM',
            'artifacts': alert_data.get('artifacts', [])
        }
        
        response = requests.post(
            'https://soar-platform/api/incidents',
            headers=headers,
            json=incident_data
        )
        return response.json()

    def create_jira_ticket(self, incident_data):
        """Create Jira ticket for tracking"""
        auth = (self.jira_creds_dict['username'], self.jira_creds_dict['token'])
        
        ticket_data = {
            'fields': {
                'project': {'key': 'SEC'},
                'summary': f"Security Incident: {incident_data['title']}",
                'description': incident_data['description'],
                'issuetype': {'name': 'Security Incident'},
                'priority': {'name': incident_data['severity']}
            }
        }
        
        response = requests.post(
            'https://your-jira-instance/rest/api/2/issue',
            auth=auth,
            headers={'Content-Type': 'application/json'},
            json=ticket_data
        )
        return response.json()

    def trigger_playbook(self, incident_id, playbook_type):
        """Trigger automated response playbook"""
        headers = {
            'Authorization': f'Bearer {self.soar_api_key}',
            'Content-Type': 'application/json'
        }
        
        playbook_data = {
            'incident_id': incident_id,
            'playbook_type': playbook_type,
            'automated': True
        }
        
        response = requests.post(
            'https://soar-platform/api/playbooks/run',
            headers=headers,
            json=playbook_data
        )
        return response.json()

@functions_framework.http
def process_soar_action(request):
    """Cloud Function entry point"""
    try:
        request_json = request.get_json()
        
        # Initialize SOAR integration
        soar = SOARIntegration()
        
        # Create incident in SOAR platform
        incident = soar.create_incident(request_json)
        
        # Create Jira ticket
        jira_ticket = soar.create_jira_ticket(incident)
        
        # Determine and trigger appropriate playbook
        if request_json.get('severity') == 'HIGH':
            playbook_result = soar.trigger_playbook(
                incident['id'],
                'immediate_response'
            )
        else:
            playbook_result = soar.trigger_playbook(
                incident['id'],
                'standard_response'
            )
        
        return json.dumps({
            'status': 'success',
            'incident_id': incident['id'],
            'jira_ticket': jira_ticket['key'],
            'playbook_execution': playbook_result['execution_id']
        }), 200
        
    except Exception as e:
        return f'Error: {str(e)}', 500
