"""
Cloud Function for automated VM isolation response
Triggered by Chronicle SIEM alerts
"""

import functions_framework
from google.cloud import compute_v1
from google.cloud import security_center_v1
import json
import os

PROJECT_ID = os.getenv('PROJECT_ID')
ZONE = os.getenv('ZONE')

@functions_framework.http
def isolate_vm(request):
    """
    Isolates a compromised VM by:
    1. Removing it from its network
    2. Creating forensics snapshot
    3. Notifying security team
    """
    try:
        request_json = request.get_json()
        
        # Extract alert details
        alert = request_json.get('alert', {})
        vm_name = alert.get('asset_name')
        alert_type = alert.get('alert_type')
        severity = alert.get('severity')

        if not all([vm_name, alert_type, severity]):
            return 'Missing required alert information', 400

        # Initialize clients
        compute_client = compute_v1.InstancesClient()
        security_client = security_center_v1.SecurityCenterClient()

        # 1. Network isolation
        instance = compute_client.get(project=PROJECT_ID, zone=ZONE, instance=vm_name)
        operation = compute_client.update_network_interface(
            project=PROJECT_ID,
            zone=ZONE,
            instance=vm_name,
            network_interface='nic0',
            network_interface_resource={
                'network': 'isolated-network'
            }
        )
        operation.result()  # Wait for completion

        # 2. Create snapshot
        snapshot_name = f"{vm_name}-forensic-{int(time.time())}"
        disk_client = compute_v1.DisksClient()
        snapshot_operation = disk_client.create_snapshot(
            project=PROJECT_ID,
            zone=ZONE,
            disk=instance.disks[0].source.split('/')[-1],
            snapshot_resource={
                'name': snapshot_name,
                'description': f'Forensic snapshot for {vm_name}'
            }
        )
        snapshot_operation.result()

        # 3. Create security finding
        finding = {
            'state': 'ACTIVE',
            'category': 'VM_ISOLATION',
            'source_properties': {
                'vm_name': vm_name,
                'alert_type': alert_type,
                'severity': severity,
                'action_taken': 'VM_ISOLATED',
                'snapshot_name': snapshot_name
            }
        }
        
        source_name = f"organizations/{PROJECT_ID}/sources/-"
        security_client.create_finding(parent=source_name, finding_id=vm_name, finding=finding)

        return json.dumps({
            'status': 'success',
            'message': f'VM {vm_name} isolated successfully',
            'snapshot': snapshot_name
        }), 200

    except Exception as e:
        return f'Error: {str(e)}', 500
