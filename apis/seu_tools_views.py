import datetime
import json
import time
import logging
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication
from rest_framework.reverse import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.http import JsonResponse, HttpResponse
from django.db import connection
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

#from .models import  APIRequestHistory#,ConfigurationManager

from .utils import (execute_oracle_stored_procedure, extract_subscription_months_from_pdf, 
                    extract_subscription_months_with_ai, 
                    call_noor_soap_service, 
                    call_moahal_soap_service, 
                    parse_moahal_soap_response, 
                    call_disability_soap_service, 
                    parse_disability_soap_response_v1,
                    call_social_security_soap_service, parse_noor_soap_response_v1, 
                    parse_social_security_soap_response,
                    call_qiyas_soap_service, 
                    parse_qiyas_soap_response,
                    create_standardized_response,
                    validate_required_fields,
                    validate_national_id,
                    validate_mobile_number,
                    validate_email, 
                    call_national_address_soap_service, 
                    parse_national_address_soap_response, 
                    # call_get_student_info_by_mobile,
                    create_api_history_record, 
                    get_history_context
                    )
from decouple import config
from authentication.views import  APITokenAuthentication
from .utils import get_requester_name
#from .models import ConfigurationManager
##from authentication.models import ProcessingHistory
import requests

User = get_user_model()
logger = logging.getLogger('apis')
logging_enabled =False #ConfigurationManager.get_config('logging.enabled', default=True)

@api_view(['GET'])
@permission_classes([IsAuthenticated])  # Allow anonymous access
def api_root(request, format=None):
    """
    Dynamic API root endpoint showing all available endpoints.
    """
    return Response({
        'message': 'SEU Tools API',
        'version': 'v1',
        'endpoints': {
            # Certificate Processing APIs
            'extract-GOSI_subscription': reverse('extract-GOSI_subscription', request=request, format=format),
            'AI_extract-GOSI_subscription': reverse('AI_extract-GOSI_subscription', request=request, format=format),
            'process-certificate': reverse('process-certificate', request=request, format=format),
            
            # Government Services APIs
            'disability': reverse('disability-api', request=request, format=format),
            'national-address': reverse('national-address-api', request=request, format=format),
            'social-security': reverse('social-security-api', request=request, format=format),
            'yaqeen': reverse('yaqeen', request=request, format=format),
            
            # Educational Services APIs
            'noor': reverse('noor-api', request=request, format=format),
            'qiyas': reverse('qiyas-api', request=request, format=format),
            'moahal': reverse('moahal-api', request=request, format=format),
            'bachelor-eligibility': reverse('bachelor-eligibility-api', request=request, format=format),
            
            # Student Information APIs
            'student-info': reverse('student-info-api', request=request, format=format),
            'student-info-by-mobile': reverse('student-info-by-mobile-api', request=request, format=format),
            'update-student-mobile': reverse('student-mobile-api', request=request, format=format),
            
            # ERP APIs
            'erp-employee-profile': reverse('erp-employee-profile-api', request=request, format=format),
            'erp-leave-insert': reverse('erp-leave-insert-api', request=request, format=format),
            'erp-leave-decree-date': reverse('erp-leave-decree-date-api', request=request, format=format),
            'erp-leave-decree-number': reverse('erp-leave-decree-number-api', request=request, format=format),
            'erp-leave-type': reverse('erp-leave-type-api', request=request, format=format),
            'erp-leave-extend-refs': reverse('erp-leave-extend-leave-ref-api', request=request, format=format),
            'erp-leave-end-refs': reverse('erp-leave-end-leave-ref-api', request=request, format=format),
            'erp-leave-return-refs': reverse('erp-leave-return-leave-ref-api', request=request, format=format),
            'erp-leave-update-refs': reverse('erp-leave-update-leave-ref-api', request=request, format=format),
            
            # Communication APIs
            'sms': reverse('sms-api', request=request, format=format),
        },
        'documentation': {
            'swagger': request.build_absolute_uri('/docs/'),
            'redoc': request.build_absolute_uri('/redoc/'),
        }
    })



@method_decorator(csrf_exempt, name='dispatch')
class ExtractSubscriptionMonthsView(APIView):

    parser_classes = [MultiPartParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication,  SessionAuthentication]
    permission_classes = [IsAuthenticated]
    

    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        if 'file' not in request.FILES:
            # Create processing history record for validation error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message="No file provided",
                requester=get_requester_name(request),
                processing_method="POST"
            )
            return Response(
                {"error": "No file provided"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        uploaded_file = request.FILES['file']
        
        # Validate file type
        if not uploaded_file.name.lower().endswith('.pdf'):
            # Create processing history record for validation error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message="Only PDF files are supported",
                requester=get_requester_name(request),
                processing_method="POST"
            )
            return Response(
                {"error": "Only PDF files are supported"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate file size (10MB limit)
        if uploaded_file.size > 10 * 1024 * 1024:
            # Create processing history record for validation error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message="File size must be less than 10MB",
                requester=get_requester_name(request),
                processing_method="POST"
            )
            return Response(
                {"error": "File size must be less than 10MB"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Read file content
            file_content = uploaded_file.read()
            
            # Process the PDF
            result = extract_subscription_months_from_pdf(file_content, uploaded_file.name)
            
            
            if result["status"] == "success":
                # Create processing history record
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="success",
                    processing_time=time.time() - start_time,
                    result=result,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                return Response(result, status=status.HTTP_200_OK)
            else:
                # Create processing history record for error
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message=result.get("error_message", "Unknown error"),
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                return Response(
                    {"detail": {
                        "message": result.get("error_message", "Unknown error"),
                        "debug_text": result.get("debug_text", [])
                    }},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        except Exception as e:
            
            
            # Create processing history record for error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message=str(e),
                requester=get_requester_name(request),
                processing_method="POST"
            )
            #logger..error(f"Error processing certificate: {error_message}")
            return Response(
                {"error": error_message}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@method_decorator(csrf_exempt, name='dispatch')
class ExtractSubscriptionMonthsByAIView(APIView):
   
    parser_classes = [MultiPartParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    
   
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        if 'file' not in request.FILES:
            # Create processing history record for validation error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message="No file provided",
                requester=get_requester_name(request),
                processing_method="POST"
            )
            return Response(
                {"error": "No file provided"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        uploaded_file = request.FILES['file']
        
        # Validate file type
        allowed_types = ['.pdf', '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff']
        if not any(uploaded_file.name.lower().endswith(ext) for ext in allowed_types):
            # Create processing history record for validation error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message="Supported file types: PDF, PNG, JPG, JPEG, GIF, BMP, TIFF",
                requester=get_requester_name(request),
                processing_method="POST"
            )
            return Response(
                {"error": "Supported file types: PDF, PNG, JPG, JPEG, GIF, BMP, TIFF"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate file size (10MB limit)
        if uploaded_file.size > 10 * 1024 * 1024:
            # Create processing history record for validation error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message="File size must be less than 10MB",
                requester=get_requester_name(request),
                processing_method="POST"
            )
            return Response(
                {"error": "File size must be less than 10MB"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Read file content
            file_content = uploaded_file.read()
            
            # Track processing start time
            processing_start_time = time.time()
            
            # Process the file with AI
            result = extract_subscription_months_with_ai(
                file_content, 
                uploaded_file.name, 
                uploaded_file.content_type
            )
            
            # Calculate processing time
            processing_end_time = time.time()
            processing_time = processing_end_time - processing_start_time
            total_time = processing_end_time - start_time
            
            if result["status"] == "success":
                # Add timing information to the response
                # result["processing_time_seconds"] = f"{processing_time:.2f}"
                # result["total_time_seconds"] = f"{total_time:.2f}"
                
                # Create processing history record
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="success",
                    processing_time=total_time,
                    result=result,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                
                # Create certificate upload record
                
                
                return Response(result, status=status.HTTP_200_OK)
            else:
                # Create processing history record for error
                
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=total_time,
                    error_message=result.get("error_message", "Unknown error"),
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                return Response(
                    {
                        "error": result.get("error_message", "Unknown error"),
                        "status": "error",
                        "details": result
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        except Exception as e:
            
            error_message = str(e)
            
            # Create processing history record for error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message=str(e),
                requester=get_requester_name(request),
                processing_method="POST"
            )
            #logger..error(f"Error processing certificate with AI: {error_message}")
            return Response(
                {"error": error_message}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@api_view(['POST'])
@authentication_classes([APITokenAuthentication,  SessionAuthentication])
@permission_classes([IsAuthenticated])
def process_certificate(request):
    """
    Process certificate endpoint.
    """
    start_time = time.time()
    
    if 'file' not in request.FILES:
        # Create processing history record for validation error
        create_api_history_record(
            user=request.user,
            endpoint=request.path,
            status_type="error",
            processing_time=time.time() - start_time,
            error_message="No file provided",
            requester=get_requester_name(request),
            processing_method="POST"
        )
        return Response(
            {"error": "No file provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    uploaded_file = request.FILES['file']
    
    try:
        # Process the file
        result = extract_subscription_months_from_pdf(uploaded_file.read(), uploaded_file.name)
        
        # Calculate processing time
        
        
        if result.get("status") == "success":
            # Create processing history record for success
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="success",
                processing_time=time.time() - start_time,
                result=result,
                requester=get_requester_name(request),
                processing_method="POST"
            )
        else:
            # Create processing history record for processing error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message=str(e),
                requester=get_requester_name(request),
                processing_method="POST"
            )
        
        return Response(result)
        
    except Exception as e:
        
        
        
        # Create processing history record for exception
        create_api_history_record(
            user=request.user,
            endpoint=request.path,
            status_type="error",
            processing_time=time.time() - start_time,
            error_message=str(e),
            requester=get_requester_name(request),
            processing_method="POST"
        )
        #logger..error(f"Error in process_certificate: {error_message}")
        return Response(
            {"error": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


class NoorAPIView(APIView):

    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    
    def get_parsers(self):
        """
        Allow both JSON and form data for this endpoint.
        """
        from rest_framework.parsers import JSONParser
        return [JSONParser(), MultiPartParser(), FormParser()]

    
    def post(self, request):
        """
        Handle POST request to call Noor SOAP service.
        """
        start_time = time.time()
        
        try:
            # Get StudentIdentifier from request
            student_identifier = request.data.get('StudentIdentifier')
            
            if not student_identifier:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="StudentIdentifier is required",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("StudentIdentifier is required {user_id: %s, endpoint: %s}", request.user, request.path)
                return Response(
                    {"error": "StudentIdentifier is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate StudentIdentifier format (basic validation)
            if not isinstance(student_identifier, str) or len(student_identifier.strip()) == 0:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="StudentIdentifier must be a non-empty string",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("StudentIdentifier must be a non-empty string {user_id: %s, endpoint: %s}", request.user, request.path)
                return Response(
                    {"error": "StudentIdentifier must be a non-empty string"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            student_identifier = student_identifier.strip()
            
            # Call Noor SOAP service
            soap_endpoint = config('NOOR_SOAP_ENDPOINT')
            soap_action = config('NOOR_SOAP_ACTION')
            
            # Define custom headers for SOAP request
            custom_headers = {
                'Content-Type': 'text/xml;charset=UTF-8',
                'SOAPAction': soap_action,
                'Connection': 'Keep-Alive',
                'Accept-Encoding': 'gzip, deflate',
                'User-Agent': 'python-requests/2.25.1',
                'Accept': '*/*'
            }
            
            soap_response = call_noor_soap_service(
                endpoint_url=soap_endpoint,
                action=soap_action,
                student_identifier=student_identifier,
                headers=custom_headers
            )
            source = "Noor"
            # print('soap_response', soap_response)
            if 'Invalid Student Id' in soap_response["soap_response"]:
                #call get_old_noor_recored
                from .utils import get_old_noor_recored
               
                old_noor_recored = get_old_noor_recored(student_identifier)
                result =  old_noor_recored
                source = "Noor DB"
            else:
                if soap_response["status"] == "success":
                    # Parse the SOAP response to extract structured data
                    parsed_data = parse_noor_soap_response_v1(soap_response["soap_response"],source=source)
                    
                    if parsed_data["status"] == "success":
                        
                        # Return the data in the GetHighSchoolCertificateResponse format
                        result = parsed_data["data"]
                      
                    else:
                        result = {
                            "status": "error",
                            "student_identifier": student_identifier,
                            "error_message": parsed_data["error_message"],
                            "error_type": parsed_data.get("error_type", "parsing_error"),
                            #"raw_soap_response": soap_response["soap_response"]
                        }
                else:
                    result = {
                        "status": "error",
                        "student_identifier": student_identifier,
                        "error_message": soap_response["error_message"],
                        "error_type": soap_response.get("error_type", "unknown")
                    }
                
           
           
            # Create processing history record
            if result.get("status") == "success":
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="success",
                    processing_time=time.time() - start_time,
                    result=result,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.info("Success {user_id: %s, endpoint: %s}", request.user, request.path)
            else:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message=result.get("error_message", "Unknown error"),
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("Unknown error {user_id: %s, endpoint: %s}", request.user, request.path)
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:

            # Create processing history record for error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message=str(e),
                requester=get_requester_name(request),
                processing_method="POST"
            )
            if logging_enabled:
                logger.error("Error in Noor API: {user_id: %s, endpoint: %s}", request.user, request.path)
            
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class DisabilityAPIView(APIView):
    """
    Disability API endpoint that integrates with MOSA Disability Report SOAP service.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_parsers(self):
        """
        Allow both JSON and form data for this endpoint.
        """
        from rest_framework.parsers import JSONParser
        return [JSONParser(), MultiPartParser(), FormParser()]

    
    def post(self, request):
        """
        Handle POST request to call Disability SOAP service.
        """
        start_time = time.time()
        
        try:
            # Get parameters from request
            identifier = request.data.get('Identifier')
            identifier_type = request.data.get('IdentifierType', 'NationalIdentity')
            
            if not identifier:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="Identifier is required",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("Identifier required {user_id: %s, endpoint: %s}", request.user, request.path)
                return Response(
                    {"error": "Identifier is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate Identifier format
            if not isinstance(identifier, str) or len(identifier.strip()) == 0:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="Identifier must be a non-empty string",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("Invalid identifier format {user_id: %s, endpoint: %s, identifier: %s}", request.user, request.path, identifier)
                return Response(
                    {"error": "Identifier must be a non-empty string"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            identifier = identifier.strip()
            
            # Call Disability SOAP service
            soap_endpoint = "http://10.4.80.25/GSBExpress/SocialAffairs/MOSADisabilityReport/DisabilityReportService.svc"
            soap_action = "http://tempuri.org/IDisabilityReportService/GetDisabilityInfo"
            
            # Define custom headers for SOAP request
            custom_headers = {
                'Content-Type': 'text/xml;charset=UTF-8',
                'SOAPAction': soap_action,
                'Connection': 'Keep-Alive',
                'Accept-Encoding': 'gzip, deflate',
                'User-Agent': 'python-requests/2.25.1',
                'Accept': '*/*'
            }
            
            soap_response = call_disability_soap_service(
                endpoint_url=soap_endpoint,
                action=soap_action,
                identifier=identifier,
                identifier_type=identifier_type,
                headers=custom_headers
            )
            
            if soap_response["status"] == "success":
                # Parse the SOAP response to extract structured data
                parsed_data = parse_disability_soap_response_v1(soap_response["soap_response"])
                
                if parsed_data["status"] == "success":
                    result = {
                        # "status": "success",
                        # "identifier": identifier,
                        "data": parsed_data
                    }
                else:
                    result = {
                        "status": "error",
                        "identifier": identifier,
                        "error_message": parsed_data["error_message"],
                        "error_type": parsed_data.get("error_type", "parsing_error"),
                        #"raw_soap_response": soap_response["soap_response"]
                    }
            else:
                result = {
                    "status": "error",
                    "identifier": identifier,
                    "error_message": soap_response["error_message"],
                    "error_type": soap_response.get("error_type", "unknown")
                }
            
           
            
            # Create processing history record
            if result.get("status") == "success":
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="success",
                    processing_time=time.time() - start_time,
                    result=result,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.info("Disability information retrieved successfully {user_id: %s, endpoint: %s, identifier: %s}", request.user, request.path, identifier)
            else:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message=result.get("error_message", "Unknown error"),
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("Disability service error {user_id: %s, endpoint: %s, identifier: %s}", request.user, request.path, identifier)
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
          
            
            # Create processing history record for error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message=str(e),
                requester=get_requester_name(request),
                processing_method="POST"
            )
            if logging_enabled:
                logger.error("Error in Disability API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class SocialSecurityAPIView(APIView):
    """
    Social Security API endpoint that integrates with MOSA Indigent Inquiry SOAP service.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_parsers(self):
        """
        Allow both JSON and form data for this endpoint.
        """
        from rest_framework.parsers import JSONParser
        return [JSONParser(), MultiPartParser(), FormParser()]

    
    def post(self, request):
        """
        Handle POST request to call Social Security SOAP service.
        """
        start_time = time.time()
        
        try:
            # Get NationalID from request
            national_id = request.data.get('NationalID')
            
            if not national_id:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="NationalID is required",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("NationalID required {user_id: %s, endpoint: %s}", request.user, request.path)
                return Response(
                    {"error": "NationalID is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate NationalID format
            if not isinstance(national_id, str) or len(national_id.strip()) == 0:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="NationalID must be a non-empty string",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("Invalid NationalID format {user_id: %s, endpoint: %s, national_id: %s}", request.user, request.path, national_id)
                return Response(
                    {"error": "NationalID must be a non-empty string"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            national_id = national_id.strip()
            
            # Call Social Security SOAP service
            soap_endpoint = "http://10.4.80.25/GSBExpress/SocialAffairs/MOSAIndigentInquiry/IndigentInquiryService.svc"
            soap_action = "http://tempuri.org/IIndigentInquiryService/GetIndigentdByNationalId"
            
            # Define custom headers for SOAP request
            custom_headers = {
                'Content-Type': 'text/xml;charset=UTF-8',
                'SOAPAction': soap_action,
                'Connection': 'Keep-Alive',
                'Accept-Encoding': 'gzip, deflate',
                'User-Agent': 'python-requests/2.25.1',
                'Accept': '*/*'
            }
            
            soap_response = call_social_security_soap_service(
                endpoint_url=soap_endpoint,
                action=soap_action,
                national_id=national_id,
                headers=custom_headers
            )
            
            if soap_response["status"] == "success":
                # Parse the SOAP response to extract structured data
                parsed_data = parse_social_security_soap_response(soap_response["soap_response"])
                
                if parsed_data["status"] == "success":
                    # Extract indigent info data safely
                    indigent_info = parsed_data.get("indigent_info") or {}
                    
                    # Helper function to safely get values
                    def safe_get(data, key, default=""):
                        if isinstance(data, dict):
                            return data.get(key, default)
                        return default
                    
                    # Return in the required Envelope format
                    result = {
                        "data":{
                        "full_name": safe_get(indigent_info, "citizen_name"),
                        "social_security_amount": safe_get(indigent_info, "social_security_amount_numeric") or safe_get(indigent_info, "social_security_amount") or 0
                        }
                    }
                                    
                else:
                    # Return error in simple format
                    result = {
                        "error": parsed_data["error_message"],
                        "error_type": parsed_data.get("error_type", "parsing_error")
                    }
            else:
                # Return error in simple format
                result = {
                    "error": soap_response["error_message"],
                    "error_type": soap_response.get("error_type", "unknown")
                }
            

            
            # Create processing history record
            # Determine if successful based on response structure
            is_success = "Envelope" in result
            error_message = result.get("error") if not is_success else None
            
            if is_success:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="success",
                    processing_time=time.time() - start_time,
                    result=result,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.info("Social security information retrieved successfully {user_id: %s, endpoint: %s, national_id: %s}", request.user, request.path, national_id)
            else:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message=error_message,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("Social security service error {user_id: %s, endpoint: %s, national_id: %s}", request.user, request.path, national_id)
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
         
          
            
            # Create processing history record for error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message=str(e),
                requester=get_requester_name(request),
                processing_method="POST"
            )
            if logging_enabled:
                logger.error("Error in Social Security API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class MoahalAPIView(APIView):
    """
    Moahal API endpoint that integrates with MOE Qualifications SOAP service.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_parsers(self):
        """
        Allow both JSON and form data for this endpoint.
        """
        from rest_framework.parsers import JSONParser
        return [JSONParser(), MultiPartParser(), FormParser()]


    def post(self, request):
        """
        Handle POST request to call Moahal SOAP service.
        """
        start_time = time.time()
        
        try:
            # Get IdentityNumber from request
            identity_number = request.data.get('IdentityNumber')
            
            if not identity_number:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="IdentityNumber is required",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("IdentityNumber required {user_id: %s, endpoint: %s}", request.user, request.path)
                return Response(
                    {"error": "IdentityNumber is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate IdentityNumber format (basic validation)
            if not isinstance(identity_number, str) or len(identity_number.strip()) == 0:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="IdentityNumber must be a non-empty string",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                return Response(
                    {"error": "IdentityNumber must be a non-empty string"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            identity_number = identity_number.strip()
            
            # Call Moahal SOAP service
            soap_endpoint = "http://10.4.80.25/GSBExpress/Education/MOEQualifications/3.0/QualificationsService.svc"
            soap_action = "http://tempuri.org/IQualificationsService/GetQualifications"
            
            # Define custom headers for SOAP request
            custom_headers = {
                'Content-Type': 'text/xml;charset=UTF-8',
                'SOAPAction': soap_action,
                'Connection': 'Keep-Alive',
                'Accept-Encoding': 'gzip, deflate',
                'User-Agent': 'python-requests/2.25.1',
                'Accept': '*/*'
            }
            
            soap_response = call_moahal_soap_service(
                endpoint_url=soap_endpoint,
                action=soap_action,
                identity_number=identity_number,
                headers=custom_headers
            )
            
           
            
            if soap_response["status"] == "success":
                # Parse the SOAP response to extract structured data
                result = parse_moahal_soap_response(soap_response["soap_response"])
                
                # Check if parsing resulted in error structure
                if "GetQualificationsResponse" in result and "GetQualificationsResult" in result["GetQualificationsResponse"]:
                    detail_object = result["GetQualificationsResponse"]["GetQualificationsResult"]["getQualificationsResponseDetailObject"]
                    print( 'Detail Object:', detail_object)
                    if "error" in detail_object:
                        # Parsing error occurred
                        error_result = {
                            "status": "error",
                            "identity_number": identity_number,
                            "error_message": detail_object["error"],
                            "error_type": detail_object.get("error_type", "parsing_error"),
                            "raw_soap_response": soap_response["soap_response"]
                        }
                        
                        # Create processing history record for error
                        create_api_history_record(
                            user=request.user,
                            endpoint=request.path,
                            status_type="error",
                            processing_time=time.time() - start_time,
                            error_message=detail_object["error"],
                            requester=get_requester_name(request),
                            processing_method="POST"
                        )
                        if logging_enabled:
                            logger.error("Moahal parsing error {user_id: %s, endpoint: %s, identity_number: %s}", request.user, request.path, identity_number)
                        return Response(error_result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
                # Success case - return the GetQualificationsResponse format directly
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="success",
                    processing_time=time.time() - start_time,
                    result=result,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.info("Moahal qualifications retrieved successfully {user_id: %s, endpoint: %s, identity_number: %s}", request.user, request.path, identity_number)
                return Response(result, status=status.HTTP_200_OK)
            else:
                # SOAP call failed
                error_result = {
                    "status": "error",
                    "identity_number": identity_number,
                    "error_message": soap_response["error_message"],
                    "error_type": soap_response.get("error_type", "unknown")
                }
                
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message=soap_response["error_message"],
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("Moahal SOAP service error {user_id: %s, endpoint: %s, identity_number: %s}", request.user, request.path, identity_number)
                return Response(error_result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as e:
            
            
            
            # Create processing history record for error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message=str(e),
                requester=get_requester_name(request),
                processing_method="POST"
            )
            if logging_enabled:
                logger.error("Error in Moahal API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class YaqeenAPIView(APIView):
    """
    Yaqeen API endpoint that calls external Yaqeen service with basic authentication.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get_parsers(self):
        """
        Allow both JSON and form data for this endpoint.
        """
        from rest_framework.parsers import JSONParser
        return [JSONParser(), MultiPartParser(), FormParser()]

    
    def post(self, request):
        
        """
        Handle POST request to call Yaqeen service.
        """
        start_time = time.time()
        
        try:
            # Get parameters from request
            ssn = request.data.get('identifier')
            dob = request.data.get('date_of_birth')
            
            # Validate required fields
            is_valid, missing_fields, error_msg = validate_required_fields(
                request.data, ['identifier', 'date_of_birth']
            )
            if not is_valid:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message=error_msg,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("Required fields missing {user_id: %s, endpoint: %s, fields: %s}", request.user, request.path, missing_fields)
                response_data = create_standardized_response(
                    status="error",
                    error=error_msg,
                    status_code=400
                )
                return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate National ID format
            is_valid_id, id_error = validate_national_id(ssn)
            if not is_valid_id:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message=id_error,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("Invalid National ID format {user_id: %s, endpoint: %s, id: %s}", request.user, request.path, ssn)
                response_data = create_standardized_response(
                    status="error",
                    error=id_error,
                    status_code=400
                )
                return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate DOB format (should be YYYY-MM)
            if ssn.startswith('1'):
                if not dob or len(dob) != 7 or dob[4] != '-':
                    create_api_history_record(
                        user=request.user,
                        endpoint=request.path,
                        status_type="error",
                        processing_time=time.time() - start_time,
                        error_message=f"Date of birth must be in YYYY-MM format. You entered {dob}",
                        requester=get_requester_name(request),
                        processing_method="POST"
                    )
                    if logging_enabled:
                        logger.error("Invalid DOB format for Saudi ID {user_id: %s, endpoint: %s, dob: %s}", request.user, request.path, dob)
                    return Response(
                        {"error": "Date of birth must be in YYYY-MM format. You entered "+dob}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else :
                    
                    # Call Yaqeen service
                    yaqeen_url = f"{settings.YAQEEN_BASE_URL}/info/nin/{ssn}/bd/{dob}"
            elif ssn.startswith('2'):
                if not dob or len(dob) != 7 or dob[2] != '-':
                    create_api_history_record(
                        user=request.user,
                        endpoint=request.path,
                        status_type="error",
                        processing_time=time.time() - start_time,
                        error_message=f"Date of birth must be in MM-YYYY format. You entered {dob}",
                        requester=get_requester_name(request),
                        processing_method="POST"
                    )
                    if logging_enabled:
                        logger.error("Invalid DOB format for non-Saudi ID {user_id: %s, endpoint: %s, dob: %s}", request.user, request.path, dob)
                    return Response(
                        {"error": "Date of birth must be in MM-YYYY format. You entered "+dob}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else:
                    
                    # Call Yaqeen service
                    yaqeen_url = f"{settings.YAQEEN_BASE_URL}/info_non_saudi/nin/{ssn}/bd/{dob}"

           
            # Setup basic authentication
            auth = (settings.YAQEEN_USERNAME, settings.YAQEEN_PASSWORD)
            # Define headers
            headers = {
                'Accept': 'application/json',
                'User-Agent': 'SEU-Tools/1.0'
            }
            
            #logger..info(f"Calling Yaqeen service: {yaqeen_url}")
            #logger..info(f"SSN: {ssn}, DOB: {dob}")
            
            # Make the API request
            response = requests.get(
                yaqeen_url,
                auth=auth,
                headers=headers,
                timeout=30  # 30-second timeout
            )
            
            # Check for HTTP errors
            response.raise_for_status()
            
            # Parse the response
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    
                    result = {
                        
                        "data": response_data
                    }
                    
                    #logger..info("Yaqeen service response received successfully")
                    
                except json.JSONDecodeError:
                    result = {
                       "data": response_data
                    }
            else:
                result = {
                    "status": "error",
                    "ssn": ssn,
                    "dob": dob,
                    "error_message": f"Yaqeen service returned status {response.status_code}",
                    "error_type": "http_error"
                }
            
          
            
            # Create processing history record
            if result.get("status") == "error":
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message=result.get("error_message", "Unknown error"),
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("Yaqeen service error {user_id: %s, endpoint: %s}", request.user, request.path)
            else:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="success",
                    processing_time=time.time() - start_time,
                    result=result,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.info("Yaqeen service success {user_id: %s, endpoint: %s}", request.user, request.path)
            # Return standardized success response
            # response_data = create_standardized_response(
            #     status="success",
            #     data=result,
            #     message="Yaqeen information retrieved successfully",
            #     status_code=200
            # )
            return Response(response_data, status=status.HTTP_200_OK)
            
        except requests.exceptions.Timeout:
           
           
            
            # Create processing history record for timeout
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message="Yaqeen service request timed out",
                requester=get_requester_name(request),
                processing_method="POST"
            )
            if logging_enabled:
                logger.error("Yaqeen service timeout {user_id: %s, endpoint: %s}", request.user, request.path)
            response_data = create_standardized_response(
                status="error",
                error="Yaqeen service request timed out",
                status_code=408
            )
            return Response(response_data, status=status.HTTP_408_REQUEST_TIMEOUT)
            
        except requests.exceptions.RequestException as e:
           
           
            
            # Create processing history record for request error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message=f"Yaqeen service request failed: {str(e)}",
                requester=get_requester_name(request),
                processing_method="POST"
            )
            if logging_enabled:
                logger.error("Yaqeen service request failed {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {
                    "status": "error",
                    "ssn": ssn,
                    "dob": dob,
                    "error_message": f"Yaqeen service request failed: {str(e)}",
                    "error_type": "request_error"
                }, 
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
           
            
            
            # Create processing history record for general error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message=str(e),
                requester=get_requester_name(request),
                processing_method="POST"
            )
            if logging_enabled:
                logger.error("Error in Yaqeen API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class QiyasAPIView(APIView):
    """
    Unified Qiyas API endpoint that integrates with Qiyas Exam Results SOAP service.
    Accepts either NationalID (for Saudi nationals) or IqamaNumber (for non-Saudi nationals).
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_parsers(self):
        """
        Allow both JSON and form data for this endpoint.
        """
        from rest_framework.parsers import JSONParser
        return [JSONParser(), MultiPartParser(), FormParser()]

   
    def post(self, request):
        """
        Handle POST request to call Qiyas SOAP service.
        """
        
        start_time = time.time()
        
        try:
            # Get parameters from request
            national_id = request.data.get('NationalID')
            exam_code = request.data.get('ExamCode') or None
            exam_specialty_code = request.data.get('ExamSpecialtyCode') or None
            inquiry_date = request.data.get('InquiryDate') or None
            
            # Validate required parameters
            if not national_id:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="NationalID is required",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("NationalID required {user_id: %s, endpoint: %s}", request.user, request.path)
                return Response(
                    {"error": "NationalID is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            if not exam_code:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="exam code is required",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("Exam code required {user_id: %s, endpoint: %s}", request.user, request.path)
                return Response(
                    {"error": "exam code is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            
            # Validate and clean input
            identifier_value = national_id.strip()
            if exam_code != None:
                exam_code = exam_code.strip()

            if exam_specialty_code != None:
                exam_specialty_code = exam_specialty_code.strip()
            if inquiry_date != None:
                inquiry_date = inquiry_date.strip()
            
            # Validate identifier format (basic validation)
            if not isinstance(identifier_value, str) or len(identifier_value) == 0:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="NationalID must be a non-empty string",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("Invalid NationalID format {user_id: %s, endpoint: %s, id: %s}", request.user, request.path, identifier_value)
                return Response(
                    {"error": "NationalID must be a non-empty string"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Call Qiyas SOAP service
            soap_endpoint = "http://10.4.80.25/GSBExpress/Education/QiyasExamResult/4.0/QiyasExamResultsService.svc"
            soap_action = "http://tempuri.org/IQiyasExamResultsService/GetExamResult"
            
            # Define custom headers for SOAP request
            custom_headers = {
                'Content-Type': 'text/xml;charset=UTF-8',
                'SOAPAction': soap_action,
                'Connection': 'Keep-Alive',
                'Accept-Encoding': 'gzip, deflate',
                'User-Agent': 'python-requests/2.25.1',
                'Accept': '*/*'
            }

            if exam_code == "01" :
                # Qudurat Exam Result
                qudurat_general_response = call_qiyas_soap_service(
                    endpoint_url=soap_endpoint,
                    action=soap_action,
                    identifier_type="NationalID",
                    identifier_value=identifier_value,
                    exam_code="01",
                    exam_specialty_code="01",
                    inquiry_date=inquiry_date,
                    headers=custom_headers
                )
                
                qudurat_general_result=None
                qudurat_scintific_result=None
                try:
                    if 'No records found' not in qudurat_general_response["soap_response"]:
                        if qudurat_general_response["status"] == "success":
                           
                            # Parse the SOAP response to extract structured data
                            parsed_data = parse_qiyas_soap_response(qudurat_general_response["soap_response"])
                            
                            if parsed_data["status"] == "success":
                                # Extract exam results data safely
                                exam_results = parsed_data.get("exam_results") or {}
                                applicant_name = {}
                                if isinstance(exam_results, dict):
                                    applicant_name = exam_results.get("applicant_name") or {}
                                
                                # Helper function to safely get values
                                def safe_get(data, key, default=""):
                                    if isinstance(data, dict):
                                        return data.get(key, default)
                                    return default
                                
                                # Return in the required Envelope format
                                qudurat_general_result = {
                                    
                                            "ExamType": safe_get(exam_results, "exam_type"),
                                            "ExamSpecialty": safe_get(exam_results, "exam_specialty"),
                                            "ExamDate": safe_get(exam_results, "exam_date"),
                                                        
                                            "name": safe_get(applicant_name, "first_name") +" "+safe_get(applicant_name, "second_name") +" "+safe_get(applicant_name, "last_name"),
                                            "ExamResult": safe_get(exam_results, "exam_score_numeric") or safe_get(exam_results, "exam_score") or 0,
                                            "ExamResultTypeAr": safe_get(exam_results, "result_type_arabic"),
                                            "ExamResultTypeEn": safe_get(exam_results, "result_type_english"),
                                            "MaxExamResult": safe_get(exam_results, "max_score_numeric") or safe_get(exam_results, "max_score") or 100,
                                                
                                            }
                                
                                # print('qudurat_general_result',qudurat_general_result)
                                        
                        else:
                            # Return error in simple format
                            result = {
                                "error": parsed_data["error_message"],
                                "error_type": parsed_data.get("error_type", "parsing_error")
                            }

                    else:
                        
                        qudurat_general_result = {
                            "error": "No records found qudurat general",
                        
                        }

                    
                except Exception as e:
                    qudurat_general = {
                                "error": parsed_data["error_message"],
                                "error_type": parsed_data.get("error_type", "parsing_error")
                            }
                
                # Qudurat Scientific Exam Result
                qudurat_scintific = call_qiyas_soap_service(
                    endpoint_url=soap_endpoint,
                    action=soap_action,
                    identifier_type="NationalID",
                    identifier_value=identifier_value,
                    exam_code="01",
                    exam_specialty_code="02",
                    inquiry_date=inquiry_date,
                    headers=custom_headers
                )
                
                
                try:
                    
                    if qudurat_scintific["status"] == "success":
                        
                        if 'No records found' not in qudurat_scintific["soap_response"]:
                            # print(' records found qudurat scintific')
                            # Parse the SOAP response to extract structured data
                            parsed_data = parse_qiyas_soap_response(qudurat_scintific["soap_response"])
                            
                            if parsed_data["status"] == "success" :
                                # Extract exam results data safely
                                exam_results = parsed_data.get("exam_results") or {}
                                applicant_name = {}
                                if isinstance(exam_results, dict):
                                    applicant_name = exam_results.get("applicant_name") or {}
                                
                                # Helper function to safely get values
                                def safe_get(data, key, default=""):
                                    if isinstance(data, dict):
                                        return data.get(key, default)
                                    return default
                                
                                # Return in the required Envelope format
                                qudurat_scintific_result = {
                                    
                                        "ExamType": safe_get(exam_results, "exam_type"),
                                        "ExamSpecialty": safe_get(exam_results, "exam_specialty"),
                                        "ExamDate": safe_get(exam_results, "exam_date"),
                                        "name": safe_get(applicant_name, "first_name") +" "+safe_get(applicant_name, "second_name") +" "+safe_get(applicant_name, "last_name"),
                                        "ExamResult": safe_get(exam_results, "exam_score_numeric") or safe_get(exam_results, "exam_score") or 0,
                                        "ExamResultTypeAr": safe_get(exam_results, "result_type_arabic"),
                                        "ExamResultTypeEn": safe_get(exam_results, "result_type_english"),
                                        "MaxExamResult": safe_get(exam_results, "max_score_numeric") or safe_get(exam_results, "max_score") or 100,
                                                
                                    }
         
                        else:
                            # print('No records found qudurat scintific')
                            qudurat_scintific_result = {
                                "error": "No records found qudurat scintific",
                            }
                except Exception as e:
                    qudurat_scintific = {
                        "error": parsed_data["error_message"],
                        "error_type": parsed_data.get("error_type", "parsing_error")
                    }
                
                
                
                # Calculate processing time
               
                
                # Create processing history record
                result = {
                    "qudurat_general": qudurat_general_result ,
                    "qudurat_scintific": qudurat_scintific_result 
                }
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="success",
                    processing_time=time.time() - start_time,
                    result=result,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.info("Qiyas Qudurat exam results retrieved successfully {user_id: %s, endpoint: %s, exam_code: %s}", request.user, request.path, exam_code)
            elif exam_code == "04":
                STEP_response = call_qiyas_soap_service(
                    endpoint_url=soap_endpoint,
                    action=soap_action,
                    identifier_type="NationalID",
                    identifier_value=identifier_value,
                    exam_code=exam_code,
                    exam_specialty_code=exam_specialty_code,
                    inquiry_date=inquiry_date,
                    headers=custom_headers
                )
                
                
                try:
                    if STEP_response["status"] == "success":
                    
                        if 'No records found' not in STEP_response["soap_response"]:
                            
                            # Parse the SOAP response to extract structured data
                            parsed_data = parse_qiyas_soap_response(STEP_response["soap_response"])
                            
                            if parsed_data["status"] == "success" :
                                # Extract exam results data safely
                                exam_results = parsed_data.get("exam_results") or {}
                                applicant_name = {}
                                if isinstance(exam_results, dict):
                                    applicant_name = exam_results.get("applicant_name") or {}
                                
                                # Helper function to safely get values
                                def safe_get(data, key, default=""):
                                    if isinstance(data, dict):
                                        return data.get(key, default)
                                    return default
                                
                                # Return in the required Envelope format
                                STEP_result = {
                                    
                                        "ExamType": safe_get(exam_results, "exam_type"),
                                        "ExamSpecialty": safe_get(exam_results, "exam_specialty"),
                                        "ExamDate": safe_get(exam_results, "exam_date"),
                                        "name": safe_get(applicant_name, "first_name") +" "+safe_get(applicant_name, "second_name") +" "+safe_get(applicant_name, "last_name"),
                                        "ExamResult": safe_get(exam_results, "exam_score_numeric") or safe_get(exam_results, "exam_score") or 0,
                                        "ExamResultTypeAr": safe_get(exam_results, "result_type_arabic"),
                                        "ExamResultTypeEn": safe_get(exam_results, "result_type_english"),
                                        "MaxExamResult": safe_get(exam_results, "max_score_numeric") or safe_get(exam_results, "max_score") or 100,
                                                
                                    }
                                        
                        else:
                            
                            STEP_result = {
                                "error": "No records found STEP",
                            }
          
                    else:
                        # Return error in simple format
                        STEP_result = {
                            "error": parsed_data["error_message"],
                            "error_type": parsed_data.get("error_type", "parsing_error")
                        }
                except Exception as e:
                    STEP_result = {
                        "error": parsed_data["error_message"],
                        "error_type": parsed_data.get("error_type", "parsing_error")
                    }
                
                
                
              
                
                # Create processing history record
                result = {
                    "STEP": STEP_result ,
                    
                }
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="success",
                    processing_time=time.time() - start_time,
                    result=result,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.info("Qiyas exam results retrieved successfully {user_id: %s, endpoint: %s, exam_code: %s}", request.user, request.path, exam_code)
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
           
           
            
            # Create processing history record for error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message=str(e),
                requester=get_requester_name(request),
                processing_method="POST"
            )
            if logging_enabled:
                logger.error("Error in Qiyas API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BachelorEligibilityAPIView(APIView):
    """
    Bachelor Eligibility API endpoint that calls Banner database stored procedure.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

   

    def post(self, request):
        """
        Handle POST request to check bachelor eligibility using Banner stored procedure.
        """
        start_time = time.time()
        
        try:
            # Get SSN from query parameters
            ssn = request.data.get('identifier')
            
            if not ssn:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="identifier parameter is required",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                return Response(
                    {"error": "identifier parameter is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate SSN format (should be 10 digits)
            if not ssn.isdigit() or len(ssn) != 10:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="SSN must be exactly 10 digits",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                return Response(
                    {"error": "SSN must be exactly 10 digits"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Test Oracle Banner database connection
            # connection_test = test_oracle_connection()
            # if connection_test["status"] != "success":

            #     return Response(
            #         {
            #             "error": "Failed to connect to Banner database", 
            #             "details": connection_test.get('message')
            #         }, 
            #         status=status.HTTP_503_SERVICE_UNAVAILABLE
            #     )
            
            # Call Banner stored procedure
            
            # Import the Banner stored procedure utility function
            from .utils import execute_oracle_function
            
            # Call the stored procedure
            procedure_result = execute_oracle_function(
                function_name='QUERYADM.F_GET_ELIGIBILITY',
                parameters=[ssn]
            )
            
            if procedure_result["status"] == "success":
                result = {
                    "status": "success",
                    "ssn": ssn,
                    "eligibility_result": procedure_result["result"],
                    "message": "Bachelor eligibility checked successfully"
                }
            else:
                result = {
                    "status": "error",
                    "ssn": ssn,
                    "error_message": procedure_result["error_message"],
                    "error_type": procedure_result.get("error_type", "procedure_error")
                }
            
            # Calculate processing time and create history record
           
            if result.get("status") == "success":
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="success",
                    processing_time=time.time() - start_time,
                    result=result,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
            else:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message=result.get("error_message", "Unknown error"),
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
           
           
            
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message=str(e),
                requester=get_requester_name(request),
                processing_method="POST"
            )
            return Response(
                {"error": "Internal server error"+str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NationalAddressAPIView(APIView):
    """
    National Address API endpoint that integrates with Wasel Address SOAP service.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_parsers(self):
        """
        Allow both JSON and form data for this endpoint.
        """
        from rest_framework.parsers import JSONParser
        return [JSONParser(), MultiPartParser(), FormParser()]

   
    def post(self, request):
        """
        Handle POST request to call National Address SOAP service.
        """
        start_time = time.time()
        
        try:
            # Get parameters from request
            identifier = request.data.get('Identifier')
            
            if not identifier:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="Identifier is required",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("Identifier required {user_id: %s, endpoint: %s}", request.user, request.path)
                return Response(
                    {"error": "Identifier is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate Identifier format
            if not isinstance(identifier, str) or len(identifier.strip()) == 0:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="Identifier must be a non-empty string",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("Invalid Identifier format {user_id: %s, endpoint: %s, identifier: %s}", request.user, request.path, identifier)
                return Response(
                    {"error": "Identifier must be a non-empty string"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            identifier = identifier.strip()
            
            # Call National Address SOAP service
            soap_endpoint = "http://10.4.80.25/GSBExpress/Communication/Post/SPWaselAddress/WaselAddressService.svc"
            soap_action = "http://tempuri.org/IWaselAddressService/GetIndividualWaselAddress"
            
            # Define custom headers for SOAP request
            custom_headers = {
                'Content-Type': 'text/xml;charset=UTF-8',
                'SOAPAction': soap_action,
                'Connection': 'Keep-Alive',
                'Accept-Encoding': 'gzip, deflate',
                'User-Agent': 'python-requests/2.25.1',
                'Accept': '*/*'
            }
            
            soap_response = call_national_address_soap_service(
                endpoint_url=soap_endpoint,
                action=soap_action,
                identifier=identifier,
                headers=custom_headers
            )
            
            if soap_response["status"] == "success":
                # Parse the SOAP response to extract structured data
                parsed_data = parse_national_address_soap_response(soap_response["soap_response"])
                
                if parsed_data["status"] == "success":
                    # Extract address info data safely
                    address_info = parsed_data.get("address_info") or {}
                  
                    # Helper function to safely get values
                    def safe_get(data, key, default=""):
                        if isinstance(data, dict):
                            return data.get(key, default)
                        return default
                    
                    # Return structured JSON response with address data
                    result = {
                        "WaselAddress": {
                            "BuildingNumber": safe_get(address_info, "building_number"),
                            "AdditionalNumber": safe_get(address_info, "additional_number"),
                            "ZipCode": safe_get(address_info, "zip_code"),
                            "UnitNumber": safe_get(address_info, "unit_number"),
                            "DistrictAreaArabic": safe_get(address_info, "district_area_arabic"),
                            "DistrictAreaEnglish": safe_get(address_info, "district_area_english"),
                            "StreetNameArabic": safe_get(address_info, "street_name_arabic"),
                            "StreetNameEnglish": safe_get(address_info, "street_name_english"),
                            "CityNameArabic": safe_get(address_info, "city_name_arabic"),
                            "CityNameEnglish": safe_get(address_info, "city_name_english"),
                            "FullName": safe_get(address_info, "full_name")
                        }
                    }
                else:
                    # Return error in simple format
                    result = {
                        "error": parsed_data["error_message"],
                        "error_type": parsed_data.get("error_type", "parsing_error")
                    }
            else:
                # Return error in simple format
                result = {
                    "error": soap_response["error_message"],
                    "error_type": soap_response.get("error_type", "unknown")
                }
            
           
           
            
            # Create processing history record
            # Determine if successful based on response structure
            is_success = "WaselAddress" in result

            
            if is_success:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="success",
                    processing_time=time.time() - start_time,
                    result=result,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.info("National address retrieved successfully {user_id: %s, endpoint: %s, identifier: %s}", request.user, request.path, identifier)
            else:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message=result.get("error"),
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                if logging_enabled:
                    logger.error("National address service error {user_id: %s, endpoint: %s, identifier: %s}", request.user, request.path, identifier)
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
           
            
            
            # Create processing history record for error
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message=str(e),
                requester=get_requester_name(request),
                processing_method="POST"
            )
            if logging_enabled:
                logger.error("Error in National Address API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )





class StudentInfoAPIView(APIView):
    """
    Student Info by Mobile API endpoint that calls Oracle stored procedure to get student information by mobile number.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_parsers(self):
        """
        Allow both JSON and form data for this endpoint.
        """
        from rest_framework.parsers import JSONParser
        return [JSONParser(), MultiPartParser(), FormParser()]

   
    def post(self, request):
        """
        Handle POST request to get student information by mobile number.
        """
        start_time = time.time()
        
        try:
            # Get mobile number from request
            student_id = request.data.get('student_id')
            mobile = request.data.get('mobile', None)
            seu_email = request.data.get('seu_email', None)
            national_id = request.data.get('national_id', None)
            
            if not student_id and not mobile and not seu_email and not national_id:
                
                if logging_enabled:
                    logger.error("Missing required parameters {user_id: %s, endpoint: %s}", request.user, request.path)
                return Response(
                    {"error": "Student ID, Mobile, SEU Email, or National ID is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            

            
            # Validate mobile number format
            if student_id:
                if not student_id.isdigit() or len(student_id.strip()) != 9:
                    
                    if logging_enabled:
                        logger.error("Invalid Student ID format {user_id: %s, endpoint: %s, student_id: %s}", request.user, request.path, student_id)
                    return Response(
                                {"error": "Student ID must be a 9 digits no characters"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
            
                student_id = student_id.strip()
            
            if mobile:
                if not mobile.isdigit() or len(mobile.strip()) != 12 or not mobile.strip().startswith('9665'):
                    
                    if logging_enabled:
                        logger.error("Invalid mobile format {user_id: %s, endpoint: %s, mobile: %s}", request.user, request.path, mobile)
                    return Response(
                        {"error": "Mobile number must be a 12 digits no characters"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                mobile = mobile.strip() if mobile else None
            
            if seu_email:
                 import re
                 email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                 if not re.match(email_pattern, seu_email.strip()):
                     
                     if logging_enabled:
                         logger.error("Invalid email format {user_id: %s, endpoint: %s, email: %s}", request.user, request.path, seu_email)
                     return Response(
                         {"error": "SEU Email must be a valid email"}, 
                         status=status.HTTP_400_BAD_REQUEST
                     )
                 seu_email = seu_email.strip()

            if national_id:
                if not national_id.isdigit() or len(national_id.strip()) != 10:
                    
                    if logging_enabled:
                        logger.error("Invalid National ID format {user_id: %s, endpoint: %s, national_id: %s}", request.user, request.path, national_id)
                    return Response(
                        {"error": "National ID must be a 10 digits no characters"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                national_id = national_id.strip()

            # print('student_id', student_id)
            # print('mobile', mobile)
            # print('seu_email', seu_email)
            # print('national_id', national_id)
             # Prepare IN parameters
            from collections import OrderedDict
            in_parameters = OrderedDict([
                 ('p_student_id', student_id if student_id else ''),      # IN parameter - pass actual value or empty string
                 ('p_mobile', mobile if mobile else ''),                  # IN parameter - pass actual value or empty string
                 ('p_seu_email', seu_email if seu_email else ''),         # IN parameter - pass actual value or empty string
                 ('p_national_id', national_id if national_id else ''),   # IN parameter - pass actual value or empty string
             ])
             
             # Prepare OUT parameters
            out_parameters = [
                 'o_result',                            # OUT parameter - cursor
                 'o_student_id',                        # OUT parameter - string
                 'o_seu_email',                         # OUT parameter - string
                 'o_national_id',                       # OUT parameter - string
             ]
            
            # Call the stored procedure
            from .utils import execute_oracle_stored_procedure
            result = execute_oracle_stored_procedure(
                procedure_name='BANINST1.GET_STUDENT_INFO4',
                in_parameters=in_parameters,
                out_parameters=out_parameters
            )
            
            # Transform the result to match the expected format
            if result.get('status') == 'success':
                output_params = result.get('output_parameters', {})
               
                # Extract student data from the cursor result
                cursor_data = output_params.get('o_result', [])
                student_data = cursor_data[0] if cursor_data else {}
                
                transformed_result = {
                    "status": "success",
                    "data": {
                        "university_id": student_data.get('UNIVERSITY_ID', ''),
                        "national_id": student_data.get('NATIONAL_ID', ''),
                        "full_name": student_data.get('FULL_NAME', ''),
                        "full_name_ar": student_data.get('FULL_NAME_AR', ''),
                        "gender": student_data.get('GENDER', ''),
                        "birth_date": student_data.get('BIRTH_DATE', ''),
                        "email": student_data.get('EMAIL', ''),
                        "mobile": student_data.get('MOBILE', ''),
                        "college": student_data.get('COLLEGE', ''),
                        "major": student_data.get('MAJOR', ''),
                        "department": student_data.get('DEPARTMENT', ''),
                        "program": student_data.get('PROGRAM', ''),
                        "program_type": student_data.get('PROGRAM_TYPE', ''),
                        "campus": student_data.get('CAMPUS', ''),
                        "student_status": student_data.get('STUDENT_STATUS', ''),
                        "passed_hours": student_data.get('PASSED_HOURS', ''),
                        "gpa": student_data.get('GPA', ''),
                        "program_credits": student_data.get('PROGRAM_CREDITS', ''),
                        "remaining_hours": student_data.get('REMAINING_HOURS', '')
                    },
                    "message": "Student information retrieved successfully"
                }
                result = transformed_result
            
                # Return the result from the stored procedure
               
                
                
                if logging_enabled:
                    logger.info("Student information retrieved successfully {user_id: %s, endpoint: %s}", request.user, request.path)

            else:
               
               
                if logging_enabled:
                    logger.error("Database error in student info API {user_id: %s, endpoint: %s}", request.user, request.path)


            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
           
           
           
            if logging_enabled:
                logger.error("Error in Student Info API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@method_decorator(csrf_exempt, name='dispatch')
class SMSAPIView(APIView):
   
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        #print('request.data', request.data)
        start_time = time.time()
        
        try:
            # Get parameters from request
            numbers = request.data.get('numbers')
            message = request.data.get('message')
            
            # Validate required parameters
            #No numbers provided
            if not numbers:
                if logging_enabled:
                    logger.error("SMS numbers required {user_id: %s, endpoint: %s}", request.user, request.path)
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="Numbers parameter is required",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                return Response(
                    {"error": "Numbers parameter is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            #No message provided
            if not message:
                if logging_enabled:
                    logger.error("SMS message required {user_id: %s, endpoint: %s}", request.user, request.path)
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="Message parameter is required",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                return Response(
                    {"error": "Message parameter is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate and clean numbers
            if isinstance(numbers, str):
                # Split comma-separated numbers and clean them
                number_list = [num.strip() for num in numbers.split(',') if num.strip()]
                #numbers formate is wrong...
                if not number_list:
                    create_api_history_record(
                        user=request.user,
                        endpoint=request.path,
                        status_type="error",
                        processing_time=time.time() - start_time,
                        error_message="No valid phone numbers provided",
                        requester=get_requester_name(request),
                        processing_method="POST"
                    )
                    return Response(
                        {"error": "No valid phone numbers provided"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Validate each number (basic validation for Saudi numbers)
                invalid_numbers = []
                for num in number_list:
                    if not num.isdigit() or len(num) != 12 or not num.startswith('9665'):
                        invalid_numbers.append(num)
                
                if invalid_numbers:
                    error_msg = f"Invalid phone numbers: {', '.join(invalid_numbers)}"
                    create_api_history_record(
                        user=request.user,
                        endpoint=request.path,
                        status_type="error",
                        processing_time=time.time() - start_time,
                        error_message=error_msg,
                        requester=get_requester_name(request),
                        processing_method="POST"
                    )
                    return Response(
                        {"error": error_msg}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # # Rejoin cleaned numbers
                # numbers = ','.join(number_list)
            
            # Validate message length
            if len(message.strip()) == 0:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="Message cannot be empty",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                return Response(
                    {"error": "Message cannot be empty"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if len(message) > 1600:  # SMS length limit
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message="Message too long (max 1600 characters)",
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
                return Response(
                    {"error": "Message too long (max 1600 characters)"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Send SMS
            response_data = self.send_sms(numbers, message)
        
            # Create history record based on response
            if response_data.get('status') == 'success' or response_data.get('code') == '1':
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="success",
                    processing_time=time.time() - start_time,
                    result=response_data,
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
            else:
                create_api_history_record(
                    user=request.user,
                    endpoint=request.path,
                    status_type="error",
                    processing_time=time.time() - start_time,
                    error_message=response_data.get('error', response_data.get('message', 'Unknown error')),
                    requester=get_requester_name(request),
                    processing_method="POST"
                )
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
           
           
            
            create_api_history_record(
                user=request.user,
                endpoint=request.path,
                status_type="error",
                processing_time=time.time() - start_time,
                error_message=str(e),
                requester=get_requester_name(request),
                processing_method="POST"
            )
            return Response(
                    {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


    def send_sms(self,  numbers,  message):

        """
        Sends an SMS message using the MSEGAT SMS Gateway API.

        Args:
            numbers (str): Comma-separated string of recipient phone numbers (e.g., "966xxxxxx,966yyyyyy").
                        For a single number, just provide that number as a string.
            message (str): The content of the SMS message.

        Returns:
            dict: The JSON response from the API, or an error dictionary if the request fails.
        """
        url = config('SMS_GATEWAY_URL')

        # Construct the JSON payload as a Python dictionary
        payload = {
            "userName": config('SMS_GATEWAY_USER'),
            "numbers": numbers,
            "userSender": config('SMS_GATEWAY_SENDER_ID'),
            "apiKey": config('SMS_GATEWAY_KEY'),
            "msg": message
        }

        # Set the Content-Type header to application/json
        headers = {
            "Content-Type": "application/json"
        }

        #print(f"Attempting to send SMS to: {numbers}")
        #print(f"Message: '{message}'")

        try:
            # Make the POST request
            # The 'json' parameter in requests automatically sets Content-Type to application/json
            # and serializes the dictionary to a JSON string.
            response = requests.post(url, headers=headers, json=payload)

            # Raise an HTTPError for bad responses (4xx or 5xx)
            response.raise_for_status()

            # Parse the JSON response
            response_data = response.json()
            # print("\nSMS API Response:")
            # print(json.dumps(response_data, indent=2)) # Pretty print the JSON response
            
            # Standardize response format
            if response_data.get('code') == '1':
                return {
                    "status": "success",
                    "message": "SMS sent successfully",
                    "numbers_count": len(numbers.split(',')),
                    "numbers": numbers,
                    "api_response": response_data
                }
            else:
                return {
                    "status": "error",
                    "error": response_data.get('message', 'SMS sending failed'),
                    "numbers": numbers,
                    "api_response": response_data
                }

        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
            print(f"Response content: {response.text}")
            return {"error": "HTTP Error", "details": str(http_err), "response_content": response.text}
        except requests.exceptions.ConnectionError as conn_err:
            print(f"Connection error occurred: {conn_err}")
            return {"error": "Connection Error", "details": str(conn_err)}
        except requests.exceptions.Timeout as timeout_err:
            print(f"Timeout error occurred: {timeout_err}")
            return {"error": "Timeout Error", "details": str(timeout_err)}
        except requests.exceptions.RequestException as req_err:
            print(f"An unexpected error occurred: {req_err}")
            return {"error": "Request Error", "details": str(req_err)}
        except json.JSONDecodeError as json_err:
            print(f"Failed to decode JSON response: {json_err}")
            print(f"Raw response content: {response.text}")
            return {"error": "JSON Decode Error", "details": str(json_err), "raw_response": response.text}

@method_decorator(csrf_exempt, name='dispatch')
class StudentMobileAPIView(APIView):
   
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        start_time = time.time()
        
        try:
            # Get parameters from request
            mobile = request.data.get('mobile')
            student_id = request.data.get('student_id')
            
            # Validate required parameters
            #No numbers provided
            if  mobile:
                if len(mobile.strip()) != 12 or not mobile.strip().isdigit() or not mobile.strip().startswith('9665'):
                    
                    return Response(
                        {"error": "Mobile number is not valid mobile number must be 13 digits and start with 9665"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:  
                mobile = None
            
                return Response(
                    {"error": "Mobile number is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            if student_id:
                if len(student_id.strip()) != 9 or not student_id.strip().isdigit():
                    return Response(
                        {"error": "Student ID is not valid student ID must be 9 digits"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                student_id = None
               
                return Response(
                    {"error": "Student ID is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                        
            
            response_data = self.update_student_mobile(student_id,mobile)
           

            
           
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            
           
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    def update_student_mobile(self, student_id, mobile_number):
        
        """
        Update student contact info
        """
        try:
            from .utils import execute_oracle_stored_procedure
            
            # Prepare IN parameters
            in_parameters = {
                'P_STD_ID': student_id, 
                'P_MOBILE': mobile_number,
            }
            
            # Prepare OUT parameters
            out_parameters = [
                'O_STATUS',
            ]
            #print('in_parameters', in_parameters)
            #print('out_parameters', out_parameters)
            result = execute_oracle_stored_procedure(
                procedure_name='BANINST1.update_student_mobile',
                in_parameters=in_parameters,
                out_parameters=out_parameters
            )
            #print('result', result)
            # Transform the result to match the expected format
            if result.get("status") == "success":
                output_params = result.get('output_parameters', {})
                return {
                    "status": "success", 
                    "message": output_params.get('O_STATUS', 'Student mobile number updated successfully'),
                    "student_id": student_id,
                    "mobile": mobile_number
                }
            else:
                return {
                    "status": "error", 
                    "message": result.get('error_message', 'Error updating student mobile number')
                }

        except Exception as e:
            print(f"Error updating student contact info: {e}")
            return {"status": "error", "message": "Error updating student mobile number "}



# ERP api points


class EmployeeProfileAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
           
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_emp_profile/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')

            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:

            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
class LeaveInsertAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/insert_leave/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
class LeaveValidateAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/validate_leave/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    

class LastLeaveAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_last_absence/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    

class LeaveReasonAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_leave_reason/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
class LeaveDestinationAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_abs_dest/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
class AccrualBalanceAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_emp_accrual_balance/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LeaveEndDateAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_emp_leave_end_date/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class AuthPersonJobAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_auth_person_job/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class AuthPersonAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_auth_person/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ValidateCancelLeaveAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/VALIDATE_CANCEL_LEAVE/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class CancelLeaveAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/CANCEL_LEAVE/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class EmployeeLeaveRefsAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_emp_abs_ref/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class CancelLeaveReasonAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_cancel_leave_reason/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class LeaveExtendAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/extend_leave/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ExtendLeaveValidateAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/extend_leave_validate/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class LeaveEndReasonAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_cancel_leave_reason/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class LeaveEndValidateAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/VALIDATE_END_LEAVE/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LeaveEndAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/END_LEAVE/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ValidateReturnLeaveAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/validate_return_leave/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class LeaveReturnAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/RETURN_LEAVE/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LeaveUpdateValidateAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/validate_update_leave/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LeaveUpdateAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/update_leave/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UpdateLeaveEndDateAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_emp_leave_end_date/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




class DecreeDateAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:

            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_decree_date/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')

            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
           
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    



class DecreeNumberAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
       
        
        try:
        
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_decree_number/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
           
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
       








class LeaveTypeAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        
        try:
           
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_absence_types/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
           
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
       



class LeaveExtendRefsAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        
        start_time = time.time()
        try:
           
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_emp_ext_abs_ref/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
           
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
           
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
       


class LeaveEndRefsAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        
        start_time = time.time()
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_emp_end_abs_ref/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
            
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)


            
        except Exception as e:
           
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
      

class LeaveReturnRefsAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        
        
        try:
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_emp_ret_abs_ref/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')

            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }

            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)


            
        except Exception as e:
           
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    

class LeaveUpdateRefsAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):

        try:
            # Get parameters from request
           
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_emp_upd_abs_ref/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')
           
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
           
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            return Response(response.json(), status=status.HTTP_200_OK)
              


            
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    

#SPM endpoints
class PRCreateAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        
        
        try:
           
            url = 'http://t-hq-erpuat-app.seu.net:8000/webservices/rest/XXX_SPM_INTEG_API/create_purchase_requestion/'
            username = 'IH_EJADA'
            password = '12345678'
            
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
           
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
                          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PRRequestDetailsAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        
       
        try:
           

            url = 'http://t-hq-erpuat-app.seu.net:8000/webservices/rest/XX_SPM_GET_PR/get_purchase_requestion/'
            username = 'IH_EJADA'
            password = '12345678'
            
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
           
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
                          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class PRAttachementAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        
       
        try:
           

            url = 'http://t-hq-erpuat-app.seu.net:8000/webservices/rest/XX_ATTCH_FILE_PR_WEBSERVICES/add_pr_file_attachment/'
            username = 'IH_EJADA'
            password = '12345678'
            
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
           
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
                          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class PRCancelAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        
       
        try:
           

            url = 'http://t-hq-erpuat-app.seu.net:8000/webservices/rest/XXX_SPM_INTEG_API/cancel_purchase_requestion/'
            username = 'IH_EJADA'
            password = '12345678'
            
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
           
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
                          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class PRWorkConfirmationCreateAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        
       
        try:
           

            url = 'http://t-hq-erpuat-app.seu.net:8000/webservices/rest/XXX_SPM_INTEG_API/create_work_confirmation/'
            username = 'IH_EJADA'
            password = '12345678'
            
            # Set the Content-Type header to application/json
            headers = {
                "Content-Type": "application/json"
            }
            
            # Use HTTP Basic Auth with username and password
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
           
            return Response(response.json(), status=status.HTTP_200_OK)

            
        except Exception as e:
                          
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

#Banner  APIs

class StudentProfileAPIView(APIView):
    """
    Student Info by Mobile API endpoint that calls Oracle stored procedure to get student information by mobile number.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_parsers(self):
        """
        Allow both JSON and form data for this endpoint.
        """
        from rest_framework.parsers import JSONParser
        return [JSONParser(), MultiPartParser(), FormParser()]

   
    def post(self, request):
        """
        Handle POST request to get student profile for the landing page by university email .
        """
        start_time = time.time()
        
        try:
           
           
            seu_email = request.data.get('email', None)
           
            
            if not seu_email:
                
                if logging_enabled:
                    logger.error("Missing required parameters student email", request.user, request.path)
                return Response(
                    {"error": "Student email is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            
            if seu_email:
                 import re
                 email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                 if not re.match(email_pattern, seu_email.strip()):
                     
                     if logging_enabled:
                         logger.error("Invalid email format {user_id: %s, endpoint: %s, email: %s}", request.user, request.path, seu_email)
                     return Response(
                         {"error": "SEU Email must be a valid email"}, 
                         status=status.HTTP_400_BAD_REQUEST
                     )
                 seu_email = seu_email.strip()

             # Prepare IN parameters
            from collections import OrderedDict
            in_parameters = OrderedDict([
                 ('p_seu_email', seu_email ),         # IN parameter - pass actual value or empty string
               
             ])
             
             # Prepare OUT parameters
            out_parameters = [
                 'o_result',                            # OUT parameter - cursor
                 'o_result_msg',                        # OUT parameter - string
             ]
            
            # Call the stored procedure
            from .utils import execute_oracle_stored_procedure
            result = execute_oracle_stored_procedure(
                procedure_name='BANINST1.GET_STUDENT_profile',
                in_parameters=in_parameters,
                out_parameters=out_parameters
            )
            
            # Transform the result to match the expected format
            if result.get('status') == 'success':
                output_params = result.get('output_parameters', {})
               
                # Extract student data from the cursor result
                cursor_data = output_params.get('o_result', [])
                student_data = cursor_data[0] if cursor_data else {}
                
                
                transformed_result = {
                    "status": "success",
                    "data": student_data,
                   
                }
                result = transformed_result
            
                
                if logging_enabled:
                    logger.info("Student profile retrieved successfully {user_id: %s, endpoint: %s}", request.user, request.path)

            else:
               
               
                if logging_enabled:
                    logger.error("Database error in student profile API {user_id: %s, endpoint: %s}", request.user, request.path)


            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
           
           
           
            if logging_enabled:
                logger.error("Error in Student Info API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class StudentTranscriptAPIView(APIView):
    """
    Student Transcript API endpoint that calls Oracle stored procedure to get student transcript by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def post(self, request):
        
        """
        Handle POST request to get student transcript by student ID.
        """
        
        start_time = time.time()
        
        try:
           
           
            student_id = request.data.get('student_id', None)
           
            
            if not student_id or len(student_id.strip()) != 9 or not student_id.strip().isdigit():
                
                if logging_enabled:
                    logger.error("Missing required parameters student ID or student id is not 9 digits", request.user, request.path)
                return Response(
                    {"error": "Student ID is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            student_id = student_id.strip()
            from queryHelper.get_student_academic_transcript import get_student_academic_transcript
            result = get_student_academic_transcript(student_id)
            
            # Check if result contains an error
            if isinstance(result, dict) and "error" in result:
                if logging_enabled:
                    logger.error("Error in student transcript API {user_id: %s, endpoint: %s, error: %s}", 
                               request.user, request.path, result.get("error"))
                
                # Determine appropriate status code
                if "not found" in result.get("error", "").lower():
                    return Response(result, status=status.HTTP_404_NOT_FOUND)
                else:
                    return Response(result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Success case
            if logging_enabled:
                logger.info("Student transcript retrieved successfully {user_id: %s, endpoint: %s}", request.user, request.path)
            
            return Response(result, status=status.HTTP_200_OK)

        except Exception as e:
            print('error', e)
            if logging_enabled:
                logger.error("Error in Student Info API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




class StudentTranscriptAPIViewSP(APIView):
    """
    Student Transcript API endpoint that calls Oracle stored procedure to get student transcript by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]


    def post(self, request):
        
        """
        Handle POST request to get student transcript by student ID.
        """

        start_time = time.time()
        
        try:
           
           
            student_id = request.data.get('student_id', None)
           
            
            if not student_id or len(student_id.strip()) != 9 or not student_id.strip().isdigit():
                
                if logging_enabled:
                    logger.error("Missing required parameters student ID or student id is not 9 digits", request.user, request.path)
                return Response(
                    {"error": "Student ID is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            student_id = student_id.strip()
             # Prepare IN parameters
            from collections import OrderedDict
            in_parameters = OrderedDict([
                 ('p_student_id', student_id ),         # IN parameter - pass actual value or empty string
                 
             ])
             
             # Prepare OUT parameters
            out_parameters = [
                'o_json',
             ]
            
            # Call the stored procedure
            from .utils import execute_oracle_stored_procedure
            result = execute_oracle_stored_procedure(
                procedure_name='BANINST1.get_student_academic_transcript',
                in_parameters=in_parameters,
                out_parameters=out_parameters
            )
            
            # Transform the result to match the expected format
            if result.get('status') == 'success':
                result = result.get('output_parameters', {}).get('o_json')
                print('result', result)

                if logging_enabled:
                    logger.info("Student profile retrieved successfully {user_id: %s, endpoint: %s}", request.user, request.path)
                
                return Response(json.loads(result), status=status.HTTP_200_OK)
            else:

                if logging_enabled:
                    logger.error("Database error in student profile API {user_id: %s, endpoint: %s}", request.user, request.path)
                return Response(
                    {"error": "Database error occurred"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except Exception as e:
            
            if logging_enabled:
                logger.error("Error in Student Info API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )





class StudentScheduleAPIView(APIView):
    """
    Student Schedule API endpoint that calls Oracle stored procedure to get student schedule by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [ JSONParser]

    
   
    def post(self, request):
        """
        Handle POST request to get student schedule by student ID.
        """
        # return  Response(
        #     {
        #         "status": "success",
        #         "message": "Student absences API is under Testing and not yet completed"
                
        #     }, 
        #     status=status.HTTP_200_OK
        # )
        start_time = time.time()
        
        try:
           
           
            student_id = request.data.get('student_id')
            semester = request.data.get('semester', None) # if none it will get  last semester
            do_print = request.data.get('do_print', True) # if none it will get  last semester
           
            
            if not student_id or len(student_id.strip()) != 9 or not student_id.strip().isdigit():
                
                if logging_enabled:
                    logger.error("Missing required parameters student ID or student id is not 9 digits", request.user, request.path)
                return Response(
                    {"error": "Student ID is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            student_id = student_id.strip()
             # Prepare IN parameters
            from collections import OrderedDict
            in_parameters = OrderedDict([
                 ('p_student_id', student_id ),         # IN parameter - pass actual value or empty string
                 ('p_term_code', '202310' ),
                          
               
             ])
             
             # Prepare OUT parameters
            out_parameters = [
                 'o_json',
             ]
            
            # Call the stored procedure
            from .utils import execute_oracle_stored_procedure
            result = execute_oracle_stored_procedure(
                procedure_name='BANINST1.get_student_schedule',
                in_parameters=in_parameters,
                out_parameters=out_parameters
            )
            
            # Transform the result to match the expected format
            if result.get('status') == 'success':
               
                o_json = result.get('output_parameters', {}).get('o_json')
               
  
            
                
                if logging_enabled:
                    logger.info("Student profile retrieved successfully {user_id: %s, endpoint: %s}", request.user, request.path)
                return Response(json.loads(o_json), status=status.HTTP_200_OK)
            else:
               
               
                if logging_enabled:
                    logger.error("Database error in student profile API {user_id: %s, endpoint: %s}", request.user, request.path)

                return Response(
                    {"error": "Database error occurred"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        except Exception as e:
           
           
           
            if logging_enabled:
                logger.error("Error in Student Info API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class StudentAbsencesAPIView(APIView):
    """
    Student Absences API endpoint that calls Oracle stored procedure to get student absences by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def post(self, request):
        """
        Handle POST request to get student absences by student ID.
        """
        return Response(
            {
                "status": "success",
                "message": "Student absences API is under development and not yet completed"
                
            }, 
            status=status.HTTP_200_OK
        )

class StudentAbsencesExcuseAPIView(APIView):
    """
    Student Absences Excuse API endpoint that calls Oracle stored procedure to get student absences excuse by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def post(self, request):
        """
        Handle POST request to get student absences excuse by student ID.
        """
        return Response(
            {
                "status": "success",
                "message": "Student absences excuse API is under development and not yet completed"
                
            }, 
            status=status.HTTP_200_OK
        )


class StudentAbsencesExcuseSubmitAPIView(APIView):
    """
    Student Absences Excuse Submit API endpoint that calls Oracle stored procedure to submit student absences excuse by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def post(self, request):
        """
        Handle POST request to submit student absences excuse by student ID.
        """
        return Response(
            {
                "status": "success",
                "message": "Student absences excuse submit API is under development and not yet completed"
                
            }, 
            status=status.HTTP_200_OK
        )



class StudentTuitionStatementAPIView(APIView):
    """
    Student Tuition Statement API endpoint that calls Oracle stored procedure to get student tuition statement by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def post(self, request):
        """
        Handle POST request to get student tuition statement by student ID.
        """
        return Response(
            {
                "status": "success",
                "message": "Student tuition statement API is under development and not yet completed"
                
            }, 
            status=status.HTTP_200_OK
        )


class StudentVerificationStatementAPIView(APIView):
    """
    Student Verification Statement API endpoint that calls Oracle stored procedure to get student verification statement by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def post(self, request):
        """
        Handle POST request to get student verification statement by student ID.
        """
        return Response(
            {
                "status": "success",
                "message": "Student verification statement API is under development and not yet completed"
                
            }, 
            status=status.HTTP_200_OK
        )


class StudentStudyDurationStatementAPIView(APIView):
    """
    Student Study Duration Statement API endpoint that calls Oracle stored procedure to get student study duration statement by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]   

    def post(self, request):
        """
        Handle POST request to get student study duration statement by student ID.
        """
        return Response(
            {
                "status": "success",
                "message": "Student study duration statement API is under development and not yet completed"
                
            }, 
            status=status.HTTP_200_OK
        )


class StudentFinalAdmissionStatementAPIView(APIView):
    """
    Student Final Admission Statement API endpoint that calls Oracle stored procedure to get student final admission statement by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]
    
    def post(self, request):
        """
        Handle POST request to get student final admission statement by student ID.
        """
        return Response(
            {
                "status": "success",
                "message": "Student final admission statement API is under development and not yet completed"
                
            }, 
            status=status.HTTP_200_OK
        )


class StudentExternalTransferStatementAPIView(APIView):
    """
    Student External Transfer Statement API endpoint that calls Oracle stored procedure to get student external transfer statement by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]
    
    def post(self, request):
        """
        Handle POST request to get student external transfer statement by student ID.
        """
        return Response(
            {
                "status": "success",
                "message": "Student external transfer statement API is under development and not yet completed"
                
            }, 
            status=status.HTTP_200_OK
        )


class StudentMedicalReportStatementAPIView(APIView):
    """
    Student Medical Report Statement API endpoint that calls Oracle stored procedure to get student medical report statement by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]
    
    def post(self, request):
        """
        Handle POST request to get student medical report statement by student ID.
        """
        return Response(
            {
                "status": "success",
                "message": "Student medical report statement API is under development and not yet completed"
                
            }, 
            status=status.HTTP_200_OK
        )


class StudentFBNonEntitlementStatementAPIView(APIView):
    """
    Student FB Non Entitlement Statement API endpoint that calls Oracle stored procedure to get student FB non entitlement statement by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]
    
    def post(self, request):
        """
        Handle POST request to get student FB non entitlement statement by student ID.
        """
        return Response(
            {
                "status": "success",
                "message": "Student FB non entitlement statement API is under development and not yet completed"
                
            }, 
            status=status.HTTP_200_OK
        )   


class StudentFinalExamsStatementAPIView(APIView):
    """
    Student Final Exams Statement API endpoint that calls Oracle stored procedure to get student final exams statement by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]
    
    def post(self, request):
        """
        Handle POST request to get student final exams statement by student ID.
        """
        return Response(
            {
                "status": "success",
                "message": "Student final exams statement API is under development and not yet completed"
                
            }, 
            status=status.HTTP_200_OK
        )
#Generic API Gateway Base Class
# class BaseAPIGatewayView(APIView):
#     """
#     Generic API Gateway that forwards requests to external services
#     """
#     parser_classes = [MultiPartParser, FormParser, JSONParser]
#     authentication_classes = [APITokenAuthentication, SessionAuthentication]
#     permission_classes = [IsAuthenticated]
    
#     # Override these in subclasses
#     target_base_url = None
#     target_endpoint = None
#     timeout = 30
    
#     def _forward_request(self, request, method='POST'):
#         """Forward request to target service"""
#         try:
#             # Build target URL
#             url = self.target_base_url + self.target_endpoint
            
#             # Forward essential headers
#             headers = {
#                 "Content-Type": request.headers.get('Content-Type', 'application/json'),
#                 "Accept": request.headers.get('Accept', 'application/json'),
#                 "P_LANG": request.headers.get('P_LANG'),
#                 "P_USER_NAME": request.headers.get('P_USER_NAME'),
#                 "x-api-key": request.headers.get('x-api-key'),
#                 "User-Agent": request.headers.get('User-Agent', 'SEU-API-Gateway/1.0'),
#             }
            
#             # Remove None values
#             headers = {k: v for k, v in headers.items() if v is not None}
            
#             # Forward request based on method
#             if method.upper() == 'POST':
#                 response = requests.post(url, headers=headers, json=request.data, timeout=self.timeout)
#             elif method.upper() == 'GET':
#                 response = requests.get(url, headers=headers, params=request.query_params, timeout=self.timeout)
#             elif method.upper() == 'PUT':
#                 response = requests.put(url, headers=headers, json=request.data, timeout=self.timeout)
#             elif method.upper() == 'DELETE':
#                 response = requests.delete(url, headers=headers, timeout=self.timeout)
#             else:
#                 raise ValueError(f"Unsupported HTTP method: {method}")
            
#             # Handle response
#             try:
#                 response_data = response.json()
#             except ValueError:
#                 response_data = response.text
            
#             return Response(
#                 response_data, 
#                 status=response.status_code,
#                 headers={'Content-Type': response.headers.get('Content-Type', 'application/json')}
#             )
            
#         except requests.exceptions.Timeout:
#             return Response(
#                 {"error": "Gateway timeout", "message": "Target service did not respond in time"}, 
#                 status=status.HTTP_504_GATEWAY_TIMEOUT
#             )
#         except requests.exceptions.ConnectionError:
#             return Response(
#                 {"error": "Service unavailable", "message": "Cannot connect to target service"}, 
#                 status=status.HTTP_503_SERVICE_UNAVAILABLE
#             )
#         except Exception as e:
#             return Response(
#                 {"error": "Internal server error", "message": str(e)}, 
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )

#ATS ERP APIs

class ATSGenerateSeqReportAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        try:
            print("Request data:", request.data)
            print("Request headers:", dict(request.headers))
            
            response = requests.post(
                'https://apiservicesprod.seu.edu.sa/seu/services/v1/generate/seq/report', 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
            print(f"Response status: {response.status_code}")
            print(f"Response headers: {dict(response.headers)}")
            
            # Handle response safely
            try:
                response_data = response.json()
                return Response(response_data, status=response.status_code)
            except ValueError:
                # If response is not JSON, return as text
                return Response(
                    {"content": response.text, "content_type": response.headers.get('Content-Type', 'unknown')}, 
                    status=response.status_code
                )

        except requests.exceptions.Timeout:
            return Response(
                {"error": "Gateway timeout", "message": "Target service did not respond in time"}, 
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            return Response(
                {"error": "Service unavailable", "message": f"Cannot connect to target service: {str(e)}"}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class ATSCreateReportAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        try:
          
            response = requests.post(
                'https://apiservicesprod.seu.edu.sa/seu/services/v1/getlookupreports', 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
         
            
            # Handle response safely
            try:
                response_data = response.json()
                return Response(response_data, status=response.status_code)
            except ValueError:
                # If response is not JSON, return as text
                return Response(
                    {"content": response.text, "content_type": response.headers.get('Content-Type', 'unknown')}, 
                    status=response.status_code
                )

        except requests.exceptions.Timeout:
            return Response(
                {"error": "Gateway timeout", "message": "Target service did not respond in time"}, 
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            return Response(
                {"error": "Service unavailable", "message": f"Cannot connect to target service: {str(e)}"}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ATSShowReportAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, *args, **kwargs):
        try:
          
            
            # Forward the request to the target API
            response = requests.get(
                'https://apiservicesprod.seu.edu.sa/seu/services/v1/show/report', 
                headers=dict(request.headers), 
                params=request.data,  # Use params for GET request instead of json
                timeout=30
            )
            
            
            
            # Check if response is PDF
            content_type = response.headers.get('Content-Type', '').lower()
            
           
            from django.http import HttpResponse
            pdf_response = HttpResponse(
                response.content, 
                content_type='application/pdf'
            )
            pdf_response['Content-Disposition'] = 'attachment; filename="report.pdf"'
            return pdf_response
            

       
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# ---------------------------------------------
# test
class ATSGetInfoOptimized(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        try:
          
            response = requests.post(
                'https://erpapi.seu.edu.sa/ords/services/v1/getinfooptimized', 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )


            # Handle response safely
            try:
                response_data = response.json()
                return Response(response_data, status=response.status_code)
            except ValueError:
                # If response is not JSON, return as text
                return Response(
                    {"content": response.text, "content_type": response.headers.get('Content-Type', 'unknown')}, 
                    status=response.status_code
                )

        except requests.exceptions.Timeout:
            return Response(
                {"error": "Gateway timeout", "message": "Target service did not respond in time"}, 
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            return Response(
                {"error": "Service unavailable", "message": f"Cannot connect to target service: {str(e)}"}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
       

# production         
class ATSGetInfoOptimizedProduction(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        try:
          
            response = requests.post(
                'https://172.30.3.116/seu/services/v1/getinfo', 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
         
            
            # Handle response safely
            try:
                response_data = response.json()
                return Response(response_data, status=response.status_code)
            except ValueError:
                # If response is not JSON, return as text
                return Response(
                    {"content": response.text, "content_type": response.headers.get('Content-Type', 'unknown')}, 
                    status=response.status_code
                )

        except requests.exceptions.Timeout:
            return Response(
                {"error": "Gateway timeout", "message": "Target service did not respond in time"}, 
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            return Response(
                {"error": "Service unavailable", "message": f"Cannot connect to target service: {str(e)}"}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
#         
class ATSLeaveTypesAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        try:
          
            response = requests.post(
                'https://erpapi.seu.edu.sa/ords/services/v1/getlookupvac', 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
         
            
            # Handle response safely
            try:
                response_data = response.json()
                return Response(response_data, status=response.status_code)
            except ValueError:
                # If response is not JSON, return as text
                return Response(
                    {"content": response.text, "content_type": response.headers.get('Content-Type', 'unknown')}, 
                    status=response.status_code
                )

        except requests.exceptions.Timeout:
            return Response(
                {"error": "Gateway timeout", "message": "Target service did not respond in time"}, 
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            return Response(
                {"error": "Service unavailable", "message": f"Cannot connect to target service: {str(e)}"}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class ATSLeaveBalanceAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        try:
          
            response = requests.post(
                'https://erpapi.seu.edu.sa/ords/services/v1/getbalance', 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
         
            
            # Handle response safely
            try:
                response_data = response.json()
                return Response(response_data, status=response.status_code)
            except ValueError:
                # If response is not JSON, return as text
                return Response(
                    {"content": response.text, "content_type": response.headers.get('Content-Type', 'unknown')}, 
                    status=response.status_code
                )

        except requests.exceptions.Timeout:
            return Response(
                {"error": "Gateway timeout", "message": "Target service did not respond in time"}, 
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            return Response(
                {"error": "Service unavailable", "message": f"Cannot connect to target service: {str(e)}"}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ATSLeaveWorkflowDetailsAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        try:
          
            response = requests.post(
                'https://erpapi.seu.edu.sa/ords/services/v1/order/vac/det/emp', 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
         
            
            # Handle response safely
            try:
                response_data = response.json()
                return Response(response_data, status=response.status_code)
            except ValueError:
                # If response is not JSON, return as text
                return Response(
                    {"content": response.text, "content_type": response.headers.get('Content-Type', 'unknown')}, 
                    status=response.status_code
                )

        except requests.exceptions.Timeout:
            return Response(
                {"error": "Gateway timeout", "message": "Target service did not respond in time"}, 
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            return Response(
                {"error": "Service unavailable", "message": f"Cannot connect to target service: {str(e)}"}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class ATSSubstitutesAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        try:
          
            response = requests.post(
                'https://erpapi.seu.edu.sa/ords/services/v1/get/replacementEmployees', 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
         
            
            # Handle response safely
            try:
                response_data = response.json()
                return Response(response_data, status=response.status_code)
            except ValueError:
                # If response is not JSON, return as text
                return Response(
                    {"content": response.text, "content_type": response.headers.get('Content-Type', 'unknown')}, 
                    status=response.status_code
                )

        except requests.exceptions.Timeout:
            return Response(
                {"error": "Gateway timeout", "message": "Target service did not respond in time"}, 
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            return Response(
                {"error": "Service unavailable", "message": f"Cannot connect to target service: {str(e)}"}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class ATSRequestEServiceAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        try:
          
            response = requests.post(
                'https://erpapi.seu.edu.sa/ords/services/v1/vac/requst', 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
         
            
            # Handle response safely
            try:
                response_data = response.json()
                return Response(response_data, status=response.status_code)
            except ValueError:
                # If response is not JSON, return as text
                return Response(
                    {"content": response.text, "content_type": response.headers.get('Content-Type', 'unknown')}, 
                    status=response.status_code
                )

        except requests.exceptions.Timeout:
            return Response(
                {"error": "Gateway timeout", "message": "Target service did not respond in time"}, 
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            return Response(
                {"error": "Service unavailable", "message": f"Cannot connect to target service: {str(e)}"}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class ATSRequestCancelAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        try:
          
            response = requests.post(
                'https://erpapi.seu.edu.sa/ords/services/v1/vac/cancelEmpLeave', 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
         
            
            # Handle response safely
            try:
                response_data = response.json()
                return Response(response_data, status=response.status_code)
            except ValueError:
                # If response is not JSON, return as text
                return Response(
                    {"content": response.text, "content_type": response.headers.get('Content-Type', 'unknown')}, 
                    status=response.status_code
                )

        except requests.exceptions.Timeout:
            return Response(
                {"error": "Gateway timeout", "message": "Target service did not respond in time"}, 
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            return Response(
                {"error": "Service unavailable", "message": f"Cannot connect to target service: {str(e)}"}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class ATSLeaveWorkflowStatusAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        try:
          
            response = requests.post(
                'https://erpapi.seu.edu.sa/ords/services/v1/vac/getworkflow/emp', 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
         
            
            # Handle response safely
            try:
                response_data = response.json()
                return Response(response_data, status=response.status_code)
            except ValueError:
                # If response is not JSON, return as text
                return Response(
                    {"content": response.text, "content_type": response.headers.get('Content-Type', 'unknown')}, 
                    status=response.status_code
                )

        except requests.exceptions.Timeout:
            return Response(
                {"error": "Gateway timeout", "message": "Target service did not respond in time"}, 
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            return Response(
                {"error": "Service unavailable", "message": f"Cannot connect to target service: {str(e)}"}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class BannerCampusesAPIView(APIView):
    """
    Student Schedule API endpoint that calls Oracle stored procedure to get student schedule by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [ JSONParser]

    
   
    def post(self, request):
        """
        Handle POST request to get student schedule by student ID.
        """
       
        start_time = time.time()
        
        try:
           
           
            camp_code = request.data.get('camp_code', 'all')
           
            
            camp_code = camp_code.strip()
             # Prepare IN parameters
            from collections import OrderedDict
            in_parameters = OrderedDict([
                 ('p_camp_code', camp_code ),         # IN parameter - pass actual value or empty string
                 
             ])
             
             # Prepare OUT parameters
            out_parameters = [
                 'p_json',
             ]
            
            # Call the stored procedure
            from .utils import execute_oracle_stored_procedure
            result = execute_oracle_stored_procedure(
                procedure_name='BANINST1.get_campus_info_final',
                in_parameters=in_parameters,
                out_parameters=out_parameters
            )
            
            # Transform the result to match the expected format
            if result.get('status') == 'success':
               
                o_json = result.get('output_parameters', {}).get('p_json')
               
  
            
                
                if logging_enabled:
                    logger.info("Campus info retrieved successfully {user_id: %s, endpoint: %s}", request.user, request.path)
                return Response(json.loads(o_json), status=status.HTTP_200_OK)
            else:
               
               
                if logging_enabled:
                    logger.error("Database error in campus info API {user_id: %s, endpoint: %s}", request.user, request.path)

                return Response(
                    {"error": "Database error occurred"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        except Exception as e:
           
           
           
            if logging_enabled:
                logger.error("Error in Campus Info API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




class BannerProgramsAPIView(APIView):
    """
    Student Schedule API endpoint that calls Oracle stored procedure to get student schedule by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [ JSONParser]

    
   
    def post(self, request):
        """
        Handle POST request to get student schedule by student ID.
        """
       
        start_time = time.time()
        
        try:

            # if  request.data.get('program_code') =='all':
            #     #call get all programs code api...
            from collections import OrderedDict
            in_parameters = OrderedDict([
                ('p_program_code',request.data.get('program_code','all')),
                ('p_page_number', request.data.get('page_number',1)),
                ('p_page_size', request.data.get('page_size',5)),

            ])
            
            # Prepare OUT parameters
            out_parameters = [
                'o_json',
            ]
            from .utils import execute_oracle_stored_procedure
            result = execute_oracle_stored_procedure(
                procedure_name='BANINST1.get_programs_info_simple',
                in_parameters=in_parameters,
                out_parameters=out_parameters
            )
            print('result', result)
            #     programs_code =list(result.get('output_parameters', {}).get('o_json'))
            #     programs_data = []
               
            #     for program_code in programs_code:
            #         program_code = program_code.strip()
                   

            #         in_parameters = OrderedDict([
            #             ('p_program_code', program_code ),         # IN parameter - pass actual value or empty string
            #             ('p_page_number', 1),
            #             ('p_page_size', 100),
            #         ])
            #         out_parameters = [
            #             'o_json',
            #         ]
            #         from .utils import execute_oracle_stored_procedure
            #         result = execute_oracle_stored_procedure(
            #             procedure_name='BANINST1.get_programs_info_simple',
            #             in_parameters=in_parameters,
            #             out_parameters=out_parameters
            #         )

            #         if result.get('status') == 'success':
                    
            #             programs_data.append(result.get('output_parameters', {}).get('o_json'))
            #         else:
            #             programs_data.append([])
            # else:
            #     programs_data = []

            return Response(json.loads(result.get('output_parameters', {}).get('o_json')), status=status.HTTP_200_OK)
        
            # if logging_enabled:
            #     logger.info("Programs info retrieved successfully {user_id: %s, endpoint: %s}", request.user, request.path)
            # return Response(json.loads(o_json), status=status.HTTP_200_OK)
            # else:
               
               
            #     if logging_enabled:
            #         logger.error("Database error in programs info API {user_id: %s, endpoint: %s}", request.user, request.path)

            #     return Response(
            #         {"error": "Database error occurred"},
            #         status=status.HTTP_500_INTERNAL_SERVER_ERROR
            #     )
        except Exception as e:
           
           
           
            if logging_enabled:
                logger.error("Error in Programs Info API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




class BannerSemestersAPIView(APIView):
    """
    Student Schedule API endpoint that calls Oracle stored procedure to get student schedule by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [ JSONParser]

    
   
    def post(self, request):
        """
        Handle POST request to get student schedule by student ID.
        """
       
        start_time = time.time()
        
        try:
           
           
            term_code = request.data.get('term_code', 'all')
           
            
            term_code = term_code.strip()
             # Prepare IN parameters
            from collections import OrderedDict
            in_parameters = OrderedDict([
                 ('p_term_code', term_code )        # IN parameter - pass actual value or empty string
                 
             ])
             
             # Prepare OUT parameters
            out_parameters = [
                 'o_json',
                 'o_result_msg',
             ]
            
            # Call the stored procedure
            from .utils import execute_oracle_stored_procedure
            result = execute_oracle_stored_procedure(
                procedure_name='BANINST1.GET_TERMS_INFO_JSON',
                in_parameters=in_parameters,
                out_parameters=out_parameters
            )
          
            # Transform the result to match the expected format
            if result.get('status') == 'success':
               
                o_json = result.get('output_parameters', {}).get('o_json')
               
  
            
                
                if logging_enabled:
                    logger.info("Programs info retrieved successfully {user_id: %s, endpoint: %s}", request.user, request.path)
                return Response(json.loads(o_json), status=status.HTTP_200_OK)
            else:
               
               
                if logging_enabled:
                    logger.error("Database error in programs info API {user_id: %s, endpoint: %s}", request.user, request.path)

                return Response(
                    {"error": "Database error occurred"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        except Exception as e:
           
           
           
            if logging_enabled:
                logger.error("Error in Programs Info API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




class BannerDepartmentsAPIView(APIView):
    """
    Student Schedule API endpoint that calls Oracle stored procedure to get student schedule by student ID.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [ JSONParser]

    
   
    def post(self, request):
        """
        Handle POST request to get student schedule by student ID.
        """
       
        start_time = time.time()
        
        try:
           
           
            # term_code = request.data.get('term_code', 'all')
           
            
           
             # Prepare IN parameters
            from collections import OrderedDict
            in_parameters = OrderedDict([
              
                 
             ])
             
             # Prepare OUT parameters
            out_parameters = [
                 'o_json',
               
             ]
            
            # Call the stored procedure
            from .utils import execute_oracle_stored_procedure
            result = execute_oracle_stored_procedure(
                procedure_name='BANINST1.GET_ALL_DEPT',
                in_parameters=in_parameters,
                out_parameters=out_parameters
            )
          
            # Transform the result to match the expected format
            if result.get('status') == 'success':
               
                o_json = result.get('output_parameters', {}).get('o_json')
               
  
            
                
                if logging_enabled:
                    logger.info("Programs info retrieved successfully {user_id: %s, endpoint: %s}", request.user, request.path)
                return Response(json.loads(o_json), status=status.HTTP_200_OK)
            else:
               
               
                if logging_enabled:
                    logger.error("Database error in programs info API {user_id: %s, endpoint: %s}", request.user, request.path)

                return Response(
                    {"error": "Database error occurred"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        except Exception as e:
           
           
           
            if logging_enabled:
                logger.error("Error in Programs Info API {user_id: %s, endpoint: %s, error: %s}", request.user, request.path, str(e))
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



# to be tested in the UNI...
class ShowReportTypesAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        try:
          
            response = requests.post(
                config('ERP_SHOW_REPORT_TYPES') , 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
         
            
            # Handle response safely
            try:
                response_data = response.json()
                return Response(response_data, status=response.status_code)
            except ValueError:
                # If response is not JSON, return as text
                return Response(
                    {"content": response.text, "content_type": response.headers.get('Content-Type', 'unknown')}, 
                    status=response.status_code
                )

        except requests.exceptions.Timeout:
            return Response(
                {"error": "Gateway timeout", "message": "Target service did not respond in time"}, 
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            return Response(
                {"error": "Service unavailable", "message": f"Cannot connect to target service: {str(e)}"}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




# Helper function to get report name from lookup table
def get_report_name_from_lookup(lookup_table, doc_type):
    """
    Extract report_name from lookup table based on doc_type
    
    Args:
        lookup_table: List of dictionaries containing doc_type and report_name
        doc_type: The document type ID to search for
        
    Returns:
        report_name string if found, None otherwise
    """
    
    if not lookup_table:
        return None
   
    for item in lookup_table:
        if item.get('doc_type') == doc_type:
            
            return item.get('report_name')
    
    return None


# to be tested in the UNI...
class ShowReportAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser,JSONParser]  # Let DRF use default parsers
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
   
    def post(self, request, *args, **kwargs):
        try:
            # Get doc_type from request
            doc_type = request.data.get('P_DOC_TYPE')
            
            if not doc_type:
                return Response(
                    {"error": "Document type is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # First step: Get report types from ERP
            report_types_response = requests.post(
                config('ERP_SHOW_REPORT_TYPES'), 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
            if report_types_response.status_code != 200:
                return Response(
                    {"error": "Failed to get report types", "message": report_types_response.text}, 
                    status=report_types_response.status_code
                )
            
            # Extract lookup table and find report_name
            report_types_data = report_types_response.json()
            lookup_table = report_types_data.get('lookupTable', [])

            # Get report_name based on doc_type
            report_name = get_report_name_from_lookup(lookup_table, int(doc_type))
            
            if not report_name:
                return Response(
                    {"error": "Report type is  not found", "message": f"No report found for document type: {doc_type}"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Add report_name to request data for the next call
            request_data = request.data.copy()
            request_data['P_REPORT_NAME'] = report_name

            #second step generate report sequence number...
            report_sequence_number_response = requests.post(
                config('ERP_GENERATE_REPORT_SEQUENCE_NO'), 
                headers=dict(request.headers), 
                json=request_data,
                timeout=30
            )
            if report_sequence_number_response.status_code != 200:
                return Response(
                    {"error": "Failed to generate report sequence number", "message": report_sequence_number_response.text}, 
                    status=report_sequence_number_response.status_code
                )
            report_sequence_number = report_sequence_number_response.json().get('REPORT_SEQ_NO')
            request_data['P_REPORT_SEQ_NO'] = report_sequence_number
            
            
            # third step: Get the actual report
            report_response = requests.get(
                config('ERP_SHOW_REPORT'), 
                headers=dict(request.headers), 
                params=request_data,
                timeout=30
            )
            # Check if response is PDF
            content_type = report_response.headers.get('Content-Type', '').lower()
            # Handle response safely
            try:
                from django.http import HttpResponse
                pdf_response = HttpResponse(
                    report_response.content, 
                    content_type='application/pdf'
                )
                pdf_response['Content-Disposition'] = 'attachment; filename="report.pdf"'
                return pdf_response
               
            except ValueError:
                # If response is not JSON, return as text
                return Response(
                    {
                        "content": report_response.text, 
                        "content_type": report_response.headers.get('Content-Type', 'unknown'),
                        "report_name": report_name,
                        "doc_type": doc_type
                    }, 
                    status=report_response.status_code
                )

        except requests.exceptions.Timeout:
            return Response(
                {"error": "Gateway timeout", "message": "Target service did not respond in time"}, 
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            return Response(
                {"error": "Service unavailable", "message": f"Cannot connect to target service: {str(e)}"}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        except Exception as e:
            return Response(
                {"error": "Internal server error", "message": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
