"""
Management command to populate API endpoints from URL configuration.
"""

from django.core.management.base import BaseCommand
from authentication.models import APIEndpoint


class Command(BaseCommand):
    help = 'Populate API endpoints from URL configuration'
    
    def handle(self, *args, **options):
        """Populate all API endpoints."""
        
        endpoints_data = [
            # Student Services
            {
                'name': 'Noor API',
                'url_pattern': 'api/v1/noor/',
                'description': 'Get student high school certificate information from Noor system',
                'category': 'student_services',
            },
            {
                'name': 'Student Info API',
                'url_pattern': 'api/v1/student-info/',
                'description': 'Get student information by ID, mobile, email, or national ID',
                'category': 'student_services',
            },
            {
                'name': 'Student Profile API',
                'url_pattern': 'api/v1/student-profile/',
                'description': 'Get detailed student profile from Banner database',
                'category': 'student_services',
            },
            {
                'name': 'Update Student Mobile API',
                'url_pattern': 'api/v1/update-student-mobile/',
                'description': 'Update student mobile number in Banner system',
                'category': 'student_services',
            },
            
            # Verification Services
            {
                'name': 'Yaqeen API',
                'url_pattern': 'api/v1/yaqeen/',
                'description': 'Verify national ID and personal information through Yaqeen',
                'category': 'verification',
            },
            {
                'name': 'Disability API',
                'url_pattern': 'api/v1/disability/',
                'description': 'Check disability status from MOSA',
                'category': 'verification',
            },
            {
                'name': 'Social Security API',
                'url_pattern': 'api/v1/social-security/',
                'description': 'Check social security benefits status',
                'category': 'verification',
            },
            {
                'name': 'Moahal API',
                'url_pattern': 'api/v1/moahal/',
                'description': 'Get academic qualifications from MOE',
                'category': 'verification',
            },
            {
                'name': 'Qudurat API',
                'url_pattern': 'api/v1/qudurat/',
                'description': 'Get Qudurat exam results from Qiyas',
                'category': 'verification',
            },
            {
                'name': 'STEP API',
                'url_pattern': 'api/v1/step/',
                'description': 'Get STEP exam results from Qiyas',
                'category': 'verification',
            },
            
            # Banner Database
            {
                'name': 'Bachelor Eligibility API',
                'url_pattern': 'api/v1/bachelor-eligibility/',
                'description': 'Check bachelor degree eligibility from Banner',
                'category': 'banner',
            },
            
            # ERP Integration - Ejadah
            {
                'name': 'Employee Profile API',
                'url_pattern': 'api/v1/erp/employee-profile/',
                'description': 'Get employee profile from ERP system',
                'category': 'erp',
            },
            {
                'name': 'PR Create API',
                'url_pattern': 'api/v1/erp/PR/create/',
                'description': 'Create purchase requisition in ERP',
                'category': 'erp',
            },
            {
                'name': 'PR Request Details API',
                'url_pattern': 'api/v1/erp/PR/request/details/',
                'description': 'Get purchase requisition details from ERP',
                'category': 'erp',
            },
            {
                'name': 'PR Attachment API',
                'url_pattern': 'api/v1/erp/PR/attachement/add/',
                'description': 'Add attachment to purchase requisition',
                'category': 'erp',
            },
            {
                'name': 'PR Cancel API',
                'url_pattern': 'api/v1/erp/PR/cancel/',
                'description': 'Cancel purchase requisition',
                'category': 'erp',
            },
            {
                'name': 'PR Work Confirmation API',
                'url_pattern': 'api/v1/erp/PR/work-confirmation/create/',
                'description': 'Create work confirmation for PR',
                'category': 'erp',
            },
            
            # ERP Integration - ATS
            {
                'name': 'ATS Generate Report API',
                'url_pattern': 'api/v1/ats/erp/generate/seq/report/',
                'description': 'Generate sequential report from ATS ERP',
                'category': 'erp',
            },
            {
                'name': 'ATS Create Report Record API',
                'url_pattern': 'api/v1/ats/erp/report/recored/create/',
                'description': 'Create report record in ATS ERP',
                'category': 'erp',
            },
            {
                'name': 'ATS Show Report API',
                'url_pattern': 'api/v1/ats/erp/report/show/',
                'description': 'Display report from ATS ERP',
                'category': 'erp',
            },
            {
                'name': 'ATS Leave Types API',
                'url_pattern': 'api/v1/ats/erp/leave/types/',
                'description': 'Get leave types from ATS ERP',
                'category': 'erp',
            },
            {
                'name': 'ATS Leave Balance API',
                'url_pattern': 'api/v1/ats/erp/leave/balance/',
                'description': 'Get employee leave balance',
                'category': 'erp',
            },
            {
                'name': 'ATS Leave Workflow Details API',
                'url_pattern': 'api/v1/ats/erp/leave/workflow/details/',
                'description': 'Get leave workflow details',
                'category': 'erp',
            },
            {
                'name': 'ATS Substitutes API',
                'url_pattern': 'api/v1/ats/erp/leave/substitutes/',
                'description': 'Get employee substitutes for leave',
                'category': 'erp',
            },
            {
                'name': 'ATS Request E-Service API',
                'url_pattern': 'api/v1/ats/erp/leave/request/e-service/',
                'description': 'Submit leave request via e-service',
                'category': 'erp',
            },
            {
                'name': 'ATS Request Cancel API',
                'url_pattern': 'api/v1/ats/erp/leave/request/cancel/',
                'description': 'Cancel leave request',
                'category': 'erp',
            },
            {
                'name': 'ATS Leave Workflow Status API',
                'url_pattern': 'api/v1/ats/erp/leave/workflow/status/',
                'description': 'Get leave workflow status',
                'category': 'erp',
            },
            
            # Utilities
            {
                'name': 'National Address API',
                'url_pattern': 'api/v1/national-address/',
                'description': 'Get national address from Wasel system',
                'category': 'utilities',
            },
            {
                'name': 'SMS API',
                'url_pattern': 'api/v1/sms/',
                'description': 'Send SMS messages',
                'category': 'utilities',
            },
            {
                'name': 'Extract GOSI Subscription API',
                'url_pattern': 'api/v1/extract-GOSI_subscription/',
                'description': 'Extract subscription months from GOSI certificate PDF',
                'category': 'utilities',
            },
            {
                'name': 'AI Extract GOSI Subscription API',
                'url_pattern': 'api/v1/AI_extract-GOSI_subscription/',
                'description': 'Extract subscription months using AI',
                'category': 'utilities',
            },
        ]
        
        created_count = 0
        updated_count = 0
        
        for endpoint_data in endpoints_data:
            endpoint, created = APIEndpoint.objects.update_or_create(
                url_pattern=endpoint_data['url_pattern'],
                defaults={
                    'name': endpoint_data['name'],
                    'description': endpoint_data['description'],
                    'category': endpoint_data['category'],
                    'is_active': True,
                }
            )
            
            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'✓ Created: {endpoint.name}')
                )
            else:
                updated_count += 1
                self.stdout.write(
                    self.style.WARNING(f'→ Updated: {endpoint.name}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'\n✓ Complete! Created: {created_count}, Updated: {updated_count}, Total: {len(endpoints_data)}'
            )
        )

