"""
Compliance Report Generator for Chronicle SIEM
"""

from google.cloud import bigquery
from google.cloud import storage
from datetime import datetime, timedelta
import pandas as pd
import json
import os

class ComplianceReporter:
    def __init__(self):
        self.project_id = os.environ['PROJECT_ID']
        self.dataset_id = os.environ['DATASET_ID']
        self.bq_client = bigquery.Client()
        self.storage_client = storage.Client()

    def generate_hipaa_report(self, start_date, end_date):
        """Generate HIPAA compliance report"""
        query = f"""
        SELECT
            timestamp,
            event_type,
            resource_id,
            compliance_status,
            violation_details
        FROM
            `{self.project_id}.{self.dataset_id}.hipaa_compliance`
        WHERE
            timestamp BETWEEN '{start_date}' AND '{end_date}'
        ORDER BY
            timestamp DESC
        """
        
        df = self.bq_client.query(query).to_dataframe()
        
        # Calculate compliance metrics
        total_events = len(df)
        compliant_events = len(df[df['compliance_status'] == 'COMPLIANT'])
        compliance_rate = (compliant_events / total_events) * 100 if total_events > 0 else 0
        
        violations_by_type = df[df['compliance_status'] == 'VIOLATION'].groupby('event_type').size()
        
        report = {
            'report_period': {
                'start_date': start_date,
                'end_date': end_date
            },
            'summary': {
                'total_events': total_events,
                'compliant_events': compliant_events,
                'compliance_rate': compliance_rate,
                'total_violations': total_events - compliant_events
            },
            'violations_by_type': violations_by_type.to_dict(),
            'detailed_violations': df[df['compliance_status'] == 'VIOLATION'].to_dict('records')
        }
        
        return report

    def generate_access_control_report(self, start_date, end_date):
        """Generate access control compliance report"""
        query = f"""
        SELECT
            principal_email,
            resource_type,
            action,
            COUNT(*) as access_count
        FROM
            `{self.project_id}.{self.dataset_id}.access_logs`
        WHERE
            timestamp BETWEEN '{start_date}' AND '{end_date}'
        GROUP BY
            principal_email,
            resource_type,
            action
        """
        
        df = self.bq_client.query(query).to_dataframe()
        
        report = {
            'report_period': {
                'start_date': start_date,
                'end_date': end_date
            },
            'access_patterns': {
                'users': len(df['principal_email'].unique()),
                'resources': len(df['resource_type'].unique()),
                'total_actions': df['access_count'].sum()
            },
            'detailed_access': df.to_dict('records')
        }
        
        return report

    def generate_data_protection_report(self, start_date, end_date):
        """Generate data protection compliance report"""
        query = f"""
        SELECT
            timestamp,
            data_type,
            protection_status,
            encryption_status,
            access_controls
        FROM
            `{self.project_id}.{self.dataset_id}.data_protection`
        WHERE
            timestamp BETWEEN '{start_date}' AND '{end_date}'
        """
        
        df = self.bq_client.query(query).to_dataframe()
        
        report = {
            'report_period': {
                'start_date': start_date,
                'end_date': end_date
            },
            'data_protection_summary': {
                'total_records': len(df),
                'encrypted_records': len(df[df['encryption_status'] == 'ENCRYPTED']),
                'protected_records': len(df[df['protection_status'] == 'PROTECTED'])
            },
            'by_data_type': df.groupby('data_type').agg({
                'encryption_status': 'value_counts',
                'protection_status': 'value_counts'
            }).to_dict()
        }
        
        return report

    def store_report(self, report_data, report_type):
        """Store compliance report in Cloud Storage"""
        bucket = self.storage_client.bucket(f"{self.project_id}-compliance-reports")
        date_str = datetime.now().strftime('%Y%m%d')
        blob = bucket.blob(f"reports/{report_type}/{date_str}.json")
        
        blob.upload_from_string(
            json.dumps(report_data),
            content_type='application/json'
        )
        
        return blob.public_url

def generate_compliance_report(event, context):
    """Cloud Function entry point for compliance report generation"""
    try:
        reporter = ComplianceReporter()
        end_date = datetime.now()
        start_date = end_date - timedelta(days=1)
        
        # Generate various compliance reports
        hipaa_report = reporter.generate_hipaa_report(start_date, end_date)
        access_report = reporter.generate_access_control_report(start_date, end_date)
        data_protection_report = reporter.generate_data_protection_report(start_date, end_date)
        
        # Store reports
        hipaa_url = reporter.store_report(hipaa_report, 'hipaa')
        access_url = reporter.store_report(access_report, 'access_control')
        data_protection_url = reporter.store_report(data_protection_report, 'data_protection')
        
        return {
            'status': 'success',
            'reports': {
                'hipaa': hipaa_url,
                'access_control': access_url,
                'data_protection': data_protection_url
            }
        }
        
    except Exception as e:
        return {'error': str(e)}, 500
