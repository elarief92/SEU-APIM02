import datetime
import json
import time
import logging
from rest_framework import viewsets, status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.views import APIView
from rest_framework.reverse import reverse
from django.utils import timezone
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.http import JsonResponse, HttpResponse
from django.db import connection
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


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
                    
                    validate_national_id,
                    validate_mobile_number,
                    validate_email, 
                    call_national_address_soap_service, 
                    parse_national_address_soap_response, 
                    # call_get_student_info_by_mobile,
                  
                    get_history_context,
                    log_info, log_warning, log_error
                    )
from decouple import config
from .utils import get_requester_name

# ProcessingHistory model removed - using APIRequestHistory instead
import requests

logger = logging.getLogger('apis')
logging_enabled = config('LOGGING_ENABLED', default=False, cast=bool)

from rest_framework.permissions import AllowAny
from rest_framework.decorators import permission_classes



@method_decorator(csrf_exempt, name='dispatch')
class ExtractSubscriptionMonthsView(APIView):

    parser_classes = [MultiPartParser]  # Let DRF use default parsers
    

    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        if 'file' not in request.FILES:
            logger.warning("ExtractSubscriptionMonths: No file provided in request")
            return Response(
                {"error": "No file provided"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        uploaded_file = request.FILES['file']
        
        # Validate file type
        if not uploaded_file.name.lower().endswith('.pdf'):
            logger.warning(f"ExtractSubscriptionMonths: Invalid file type uploaded - {uploaded_file.name}")
            return Response(
                {"error": "Only PDF files are supported"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate file size (10MB limit)
        if uploaded_file.size > 10 * 1024 * 1024:
            logger.warning(
                f"ExtractSubscriptionMonths: File size too large - "
                f"{uploaded_file.size / (1024*1024):.2f}MB (max 10MB)"
            )
            return Response(
                {"error": "File size must be less than 10MB"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Read file content
            file_content = uploaded_file.read()
            
            logger.info(
                f"ExtractSubscriptionMonths: Processing PDF file - {uploaded_file.name} "
                f"({uploaded_file.size / 1024:.2f}KB)"
            )
            
            # Process the PDF
            result = extract_subscription_months_from_pdf(file_content, uploaded_file.name)
            
            if result["status"] == "success":
                duration = time.time() - start_time
                logger.info(
                    f"ExtractSubscriptionMonths: Successfully processed {uploaded_file.name} "
                    f"in {duration:.2f}s"
                )
                return Response(result, status=status.HTTP_200_OK)
            else:
                error_msg = result.get("error_message", "Unknown error")
                logger.warning(
                    f"ExtractSubscriptionMonths: Processing failed for {uploaded_file.name} - {error_msg}"
                )
                return Response(
                    {"detail": {
                        "message": error_msg,
                        "debug_text": result.get("debug_text", [])
                    }},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"ExtractSubscriptionMonths: Exception processing {uploaded_file.name} "
                f"after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error processing PDF file"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@method_decorator(csrf_exempt, name='dispatch')
class ExtractSubscriptionMonthsByAIView(APIView):
   
    parser_classes = [MultiPartParser]  # Let DRF use default parsers
    
   
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        if 'file' not in request.FILES:
            logger.warning("ExtractSubscriptionMonthsByAI: No file provided in request")
            return Response(
                {"error": "No file provided"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        uploaded_file = request.FILES['file']
        
        # Validate file type
        allowed_types = ['.pdf', '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff']
        if not any(uploaded_file.name.lower().endswith(ext) for ext in allowed_types):
            logger.warning(
                f"ExtractSubscriptionMonthsByAI: Invalid file type uploaded - {uploaded_file.name}"
            )
            return Response(
                {"error": "Supported file types: PDF, PNG, JPG, JPEG, GIF, BMP, TIFF"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate file size (10MB limit)
        if uploaded_file.size > 10 * 1024 * 1024:
            logger.warning(
                f"ExtractSubscriptionMonthsByAI: File size too large - "
                f"{uploaded_file.size / (1024*1024):.2f}MB (max 10MB)"
            )
            return Response(
                {"error": "File size must be less than 10MB"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Read file content
            file_content = uploaded_file.read()
            
            logger.info(
                f"ExtractSubscriptionMonthsByAI: Processing file with AI - {uploaded_file.name} "
                f"({uploaded_file.size / 1024:.2f}KB, type: {uploaded_file.content_type})"
            )
            
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
                logger.info(
                    f"ExtractSubscriptionMonthsByAI: Successfully processed {uploaded_file.name} "
                    f"in {total_time:.2f}s (AI processing: {processing_time:.2f}s)"
                )
                return Response(result, status=status.HTTP_200_OK)
            else:
                error_msg = result.get("error_message", "Unknown error")
                logger.warning(
                    f"ExtractSubscriptionMonthsByAI: Processing failed for {uploaded_file.name} "
                    f"after {total_time:.2f}s - {error_msg}"
                )
                return Response(
                    {
                        "error": error_msg,
                        "status": "error",
                        "details": result
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"ExtractSubscriptionMonthsByAI: Exception processing {uploaded_file.name} "
                f"after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error processing file with AI"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@api_view(['POST'])
def process_certificate(request):
    """
    Process certificate endpoint.
    """
    start_time = time.time()
    
    if 'file' not in request.FILES:
        logger.warning("ProcessCertificate: No file provided in request")
        return Response(
            {"error": "No file provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    uploaded_file = request.FILES['file']
    
    # Validate file type
    if not uploaded_file.name.lower().endswith('.pdf'):
        logger.warning(f"ProcessCertificate: Invalid file type uploaded - {uploaded_file.name}")
        return Response(
            {"error": "Only PDF files are supported"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        logger.info(
            f"ProcessCertificate: Processing certificate - {uploaded_file.name} "
            f"({uploaded_file.size / 1024:.2f}KB)"
        )
        
        # Process the file
        result = extract_subscription_months_from_pdf(uploaded_file.read(), uploaded_file.name)
        
        duration = time.time() - start_time
        logger.info(
            f"ProcessCertificate: Successfully processed {uploaded_file.name} in {duration:.2f}s"
        )
        
        return Response(result)
        
    except Exception as e:
        duration = time.time() - start_time
        logger.error(
            f"ProcessCertificate: Exception processing {uploaded_file.name} "
            f"after {duration:.2f}s - {str(e)}",
            exc_info=True
        )
        return Response(
            {"error": "Internal server error processing certificate"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


class NoorAPIView(APIView):

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
            student_identifier = request.data.get('Identifier')
            
            if not student_identifier:
                logger.warning(
                    f"NoorAPI: Missing Identifier in request"
                )
                return Response(
                    {"error": "Identifier is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate StudentIdentifier format (basic validation)
            if not isinstance(student_identifier, str) or len(student_identifier.strip()) == 0:
                logger.warning(
                    f"NoorAPI: Invalid Identifier format - must be non-empty string"
                )
                return Response(
                    {"error": "Identifier must be a non-empty string"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            student_identifier = student_identifier.strip()
            
            logger.info(f"NoorAPI: Processing request for student identifier: {student_identifier}")
            
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
            
            if 'Invalid Student Id' in soap_response["soap_response"]:
                logger.info(
                    f"NoorAPI: Student ID not found in Noor service, checking database - {student_identifier}"
                )
                from .utils import get_old_noor_recored
                old_noor_recored = get_old_noor_recored(student_identifier)
                result = old_noor_recored
                source = "Noor DB"
            else:
                if soap_response["status"] == "success":
                    # Parse the SOAP response to extract structured data
                    parsed_data = parse_noor_soap_response_v1(soap_response["soap_response"], source=source)
                    
                    if parsed_data["status"] == "success":
                        result = parsed_data["data"]
                    else:
                        logger.warning(
                            f"NoorAPI: Failed to parse SOAP response for {student_identifier} - "
                            f"{parsed_data['error_message']}"
                        )
                        result = {
                            "status": "error",
                            "student_identifier": student_identifier,
                            "error_message": parsed_data["error_message"],
                            "error_type": parsed_data.get("error_type", "parsing_error"),
                        }
                else:
                    logger.warning(
                        f"NoorAPI: SOAP service error for {student_identifier} - "
                        f"{soap_response['error_message']}"
                    )
                    result = {
                        "status": "error",
                        "student_identifier": student_identifier,
                        "error_message": soap_response["error_message"],
                        "error_type": soap_response.get("error_type", "unknown")
                    }
            
            # Log final result
            duration = time.time() - start_time
            if result.get("status") == "success":
                logger.info(
                    f"NoorAPI: Successfully processed {student_identifier} from {source} "
                    f"in {duration:.2f}s"
                )
            else:
                logger.warning(
                    f"NoorAPI: Failed to process {student_identifier} from {source} "
                    f"in {duration:.2f}s - {result.get('error_message', 'Unknown error')}"
                )
            
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"NoorAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class DisabilityAPIView(APIView):
    """
    Disability API endpoint that integrates with MOSA Disability Report SOAP service.
    """
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
                logger.warning("DisabilityAPI: Missing Identifier in request")
                return Response(
                    {"error": "Identifier is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate Identifier format
            if not isinstance(identifier, str) or len(identifier.strip()) == 0:
                logger.warning("DisabilityAPI: Invalid Identifier format - must be non-empty string")
                return Response(
                    {"error": "Identifier must be a non-empty string"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            identifier = identifier.strip()
            
            logger.info(
                f"DisabilityAPI: Processing request for identifier: {identifier}, "
                f"type: {identifier_type}"
            )
            
            # Call Disability SOAP service
            soap_endpoint = config('DISABILITY_SOAP_ENDPOINT')
            soap_action = config('DISABILITY_SOAP_ACTION')
            
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
                        "data": parsed_data
                    }
                else:
                    logger.warning(
                        f"DisabilityAPI: Failed to parse SOAP response for {identifier} - "
                        f"{parsed_data['error_message']}"
                    )
                    result = {
                        "status": "error",
                        "identifier": identifier,
                        "error_message": parsed_data["error_message"],
                        "error_type": parsed_data.get("error_type", "parsing_error"),
                    }
            else:
                logger.warning(
                    f"DisabilityAPI: SOAP service error for {identifier} - "
                    f"{soap_response['error_message']}"
                )
                result = {
                    "status": "error",
                    "identifier": identifier,
                    "error_message": soap_response["error_message"],
                    "error_type": soap_response.get("error_type", "unknown")
                }
            
            # Log final result
            duration = time.time() - start_time
            if result.get("status") == "success" or result.get("data"):
                logger.info(
                    f"DisabilityAPI: Successfully processed {identifier} "
                    f"(type: {identifier_type}) in {duration:.2f}s"
                )
            else:
                logger.warning(
                    f"DisabilityAPI: Failed to process {identifier} "
                    f"(type: {identifier_type}) in {duration:.2f}s - "
                    f"{result.get('error_message', 'Unknown error')}"
                )
            
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"DisabilityAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class SocialSecurityAPIView(APIView):
    """
    Social Security API endpoint that integrates with MOSA Indigent Inquiry SOAP service.
    """
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
            national_id = request.data.get('Identifier')
            
            if not national_id:
                logger.warning("SocialSecurityAPI: Missing Identifier in request")
                return Response(
                    {"error": "Identifier is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate NationalID format
            if not isinstance(national_id, str) or len(national_id.strip()) == 0:
                logger.warning("SocialSecurityAPI: Invalid Identifier format - must be non-empty string")
                return Response(
                    {"error": "Identifier must be a non-empty string"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            national_id = national_id.strip()
            
            logger.info(f"SocialSecurityAPI: Processing request for national ID: {national_id}")
            
            # Call Social Security SOAP service
            soap_endpoint = config('SOCIAL_SECURITY_SOAP_ENDPOINT')
            soap_action = config('SOCIAL_SECURITY_SOAP_ACTION')
            
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
                        "data": {
                            "full_name": safe_get(indigent_info, "citizen_name"),
                            "social_security_amount": safe_get(indigent_info, "social_security_amount_numeric") or safe_get(indigent_info, "social_security_amount") or 0
                        },
                        'status': 'success',
                    }
                else:
                    logger.info(f"SocialSecurityAPI: No record found for {national_id}")
                    result = {
                        'status': 'success',
                        "data": "No record found"
                    }
            else:
                logger.warning(
                    f"SocialSecurityAPI: SOAP service error for {national_id} - "
                    f"{soap_response['error_message']}"
                )
                result = {
                    "error": soap_response["error_message"],
                    "error_type": soap_response.get("error_type", "unknown")
                }
            
            # Log final result
            duration = time.time() - start_time
            if result.get("status") == "success":
                logger.info(
                    f"SocialSecurityAPI: Successfully processed {national_id} in {duration:.2f}s"
                )
            else:
                logger.warning(
                    f"SocialSecurityAPI: Failed to process {national_id} in {duration:.2f}s"
                )
            
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"SocialSecurityAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class MoahalAPIView(APIView):
    """
    Moahal API endpoint that integrates with MOE Qualifications SOAP service.
    """
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
            identity_number = request.data.get('Identifier')
            
            if not identity_number:
                logger.warning("MoahalAPI: Missing Identifier in request")
                return Response(
                    {"error": "Identifier is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate IdentityNumber format (basic validation)
            if not isinstance(identity_number, str) or len(identity_number.strip()) == 0:
                logger.warning("MoahalAPI: Invalid Identifier format - must be non-empty string")
                return Response(
                    {"error": "IdentityNumber must be a non-empty string"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            identity_number = identity_number.strip()
            
            logger.info(f"MoahalAPI: Processing request for identity number: {identity_number}")
            
            # Call Moahal SOAP service
            soap_endpoint = config('MOAHAL_SOAP_ENDPOINT')
            soap_action = config('MOAHAL_SOAP_ACTION')
            
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
                    
                    if "error" in detail_object:
                        # Parsing error occurred
                        duration = time.time() - start_time
                        logger.error(
                            f"MoahalAPI: Parsing error for {identity_number} - "
                            f"{detail_object['error']}"
                        )
                        error_result = {
                            "status": "error",
                            "identity_number": identity_number,
                            "error_message": detail_object["error"],
                            "error_type": detail_object.get("error_type", "parsing_error"),
                            "raw_soap_response": soap_response["soap_response"]
                        }
                        return Response(error_result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
                duration = time.time() - start_time
                logger.info(
                    f"MoahalAPI: Successfully processed {identity_number} in {duration:.2f}s"
                )
                return Response(result, status=status.HTTP_200_OK)
            else:
                # SOAP call failed
                duration = time.time() - start_time
                logger.error(
                    f"MoahalAPI: SOAP service error for {identity_number} - "
                    f"{soap_response['error_message']}"
                )
                error_result = {
                    "status": "error",
                    "identity_number": identity_number,
                    "error_message": soap_response["error_message"],
                    "error_type": soap_response.get("error_type", "unknown")
                }
                return Response(error_result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"MoahalAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class YaqeenAPIView(APIView):
    """
    Yaqeen API endpoint that calls external Yaqeen service with basic authentication.
    """
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
            
            if not ssn or not dob:
                logger.warning("YaqeenAPI: Missing required fields - identifier or date_of_birth")
                return Response(
                    {"status": "error", 
                    "error": "identifier and date_of_birth are required"}
                    , status=status.HTTP_400_BAD_REQUEST
                    )
            
            # Validate National ID format
            # Convert identifier to digits only (remove any non-digit characters)
            ssn_digits = ''.join(filter(str.isdigit, str(ssn)))
            if not ssn_digits or len(ssn_digits) != 10:
                logger.warning(f"YaqeenAPI: Invalid identifier format - {ssn} (must be 10 digits)")
                return Response({"status": "error", "error": "identifier must be a 10 digits no characters"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate DOB format (should be YYYY-MM)
            if ssn.startswith('1'):
                if not dob or len(dob) != 7 or dob[4] != '-':
                    logger.warning(f"YaqeenAPI: Invalid DOB format for Saudi ID - {dob} (expected YYYY-MM)")
                    return Response(
                        {"error": "Date of birth must be in YYYY-MM format i.e. 1440-01. You entered "+dob}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else:
                    # Call Yaqeen service
                    yaqeen_url = f"{settings.YAQEEN_BASE_URL}/info/nin/{ssn}/bd/{dob}"
                    id_type = "Saudi"
            elif ssn.startswith('2'):
                if not dob or len(dob) != 7 or dob[2] != '-':
                    logger.warning(f"YaqeenAPI: Invalid DOB format for non-Saudi ID - {dob} (expected MM-YYYY)")
                    return Response(
                        {"error": "Date of birth must be in MM-YYYY format i.e. 01-1990. You entered "+dob}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else:
                    # Call Yaqeen service
                    yaqeen_url = f"{settings.YAQEEN_BASE_URL}/info_non_saudi/nin/{ssn}/bd/{dob}"
                    id_type = "Non-Saudi"
            else:
                logger.warning(f"YaqeenAPI: Unknown ID type - {ssn} (must start with 1 or 2)")
                return Response(
                    {"error": "Identifier must start with 1 (Saudi) or 2 (Non-Saudi)"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            logger.info(f"YaqeenAPI: Processing request for {id_type} ID: {ssn}, DOB: {dob}")
            
            # Setup basic authentication
            auth = (settings.YAQEEN_USERNAME, settings.YAQEEN_PASSWORD)
            # Define headers
            headers = {
                'Accept': 'application/json',
                'User-Agent': 'SEU-Tools/1.0'
            }

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
                result = response.json()
                duration = time.time() - start_time
                logger.info(
                    f"YaqeenAPI: Successfully processed {id_type} ID {ssn} in {duration:.2f}s"
                )
            else:
                logger.warning(f"YaqeenAPI: Unexpected status code {response.status_code} for {ssn}")
                result = {"status": "error", "message": f"Unexpected status code: {response.status_code}"}
                
            return Response(result, status=status.HTTP_200_OK)
     
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"YaqeenAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {
                "message": "Internal server error", 
                "status": "error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class QudaratAPIView(APIView):
    """
    Unified Qudarat API endpoint that integrates with Qudarat Exam Results SOAP service.
    Accepts either NationalID (for Saudi nationals) or IqamaNumber (for non-Saudi nationals).
    """
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
            national_id = request.data.get('Identifier')
            exam_code = '01'
            inquiry_date = request.data.get('InquiryDate') or None
            
            # Validate required parameters
            if not national_id:
                logger.warning("QudaratAPI: Missing Identifier in request")
                return Response(
                    {"error": "NationalID is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate and clean input
            identifier_value = national_id.strip()
            # Validate identifier format (basic validation)
            if not isinstance(identifier_value, str) or len(identifier_value) != 10:
                logger.warning(f"QudaratAPI: Invalid Identifier format - {identifier_value} (must be 10 digits)")
                return Response(
                    {"error": "NationalID must be a 10-digit string"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            logger.info(f"QudaratAPI: Processing request for ID: {identifier_value}")
            
            # Call Qiyas SOAP service
            soap_endpoint = config('QIYAS_SOAP_ENDPOINT')
            soap_action = config('QIYAS_SOAP_ACTION')
            
            # Define custom headers for SOAP request
            custom_headers = {
                'Content-Type': 'text/xml;charset=UTF-8',
                'SOAPAction': soap_action,
                'Connection': 'Keep-Alive',
                'Accept-Encoding': 'gzip, deflate',
                'User-Agent': 'python-requests/2.25.1',
                'Accept': '*/*'
            }

            # Qudurat General Exam Result
            logger.debug(f"QudaratAPI: Fetching general exam results for {identifier_value}")
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
            logger.debug(f"QudaratAPI: Fetching scientific exam results for {identifier_value}")
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
                        qudurat_scintific_result = {
                            "error": "No records found qudurat scintific",
                        }
            except Exception as e:
                logger.warning(f"QudaratAPI: Error parsing scientific exam results - {str(e)}")
                qudurat_scintific_result = {
                    "error": "Error processing scientific exam results",
                    "error_type": "parsing_error"
                }
                
            # Build final result
            result = {
                "qudurat_general": qudurat_general_result,
                "qudurat_scintific": qudurat_scintific_result 
            }
            
            duration = time.time() - start_time
            logger.info(
                f"QudaratAPI: Successfully processed {identifier_value} in {duration:.2f}s "
                f"(General: {'found' if qudurat_general_result and 'error' not in qudurat_general_result else 'not found'}, "
                f"Scientific: {'found' if qudurat_scintific_result and 'error' not in qudurat_scintific_result else 'not found'})"
            )
            
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"QudaratAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class STEPAPIView(APIView):
    """
    Unified Qiyas API endpoint that integrates with Qiyas Exam Results SOAP service.
    Accepts either NationalID (for Saudi nationals) or IqamaNumber (for non-Saudi nationals).
    """
    parser_classes = [MultiPartParser, FormParser]

    def get_parsers(self):
        """
        Allow both JSON and form data for this endpoint.
        """
        from rest_framework.parsers import JSONParser
        return [JSONParser(), MultiPartParser(), FormParser()]

   
    def post(self, request):
        """
        Handle POST request to call Qiyas SOAP service for STEP exam.
        """
        
        start_time = time.time()
        exam_code = '04'  # STEP exam code
        
        try:
            # Get parameters from request
            national_id = request.data.get('Identifier')
            inquiry_date = request.data.get('InquiryDate') or None
            
            # Validate required parameters
            if not national_id:
                logger.warning("STEPAPI: Missing Identifier in request")
                return Response(
                    {"error": "Identifier is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate and clean input
            identifier_value = national_id.strip()
            
            if inquiry_date != None:
                inquiry_date = inquiry_date.strip()
            
            # Validate identifier format (basic validation)
            if not isinstance(identifier_value, str) or len(identifier_value) != 10:
                logger.warning(f"STEPAPI: Invalid Identifier format - {identifier_value} (must be 10 digits)")
                return Response(
                    {"error": "NationalID must be a 10-digit string"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            logger.info(f"STEPAPI: Processing STEP exam request for ID: {identifier_value}")
            
            # Call Qiyas SOAP service
            # STEP AND QUDURAT HAVE THE SAME SOAP SERVICE
            soap_endpoint = config('QIYAS_SOAP_ENDPOINT')
            soap_action = config('QIYAS_SOAP_ACTION')
            
            # Define custom headers for SOAP request
            custom_headers = {
                'Content-Type': 'text/xml;charset=UTF-8',
                'SOAPAction': soap_action,
                'Connection': 'Keep-Alive',
                'Accept-Encoding': 'gzip, deflate',
                'User-Agent': 'python-requests/2.25.1',
                'Accept': '*/*'
            }

            logger.debug(f"STEPAPI: Fetching STEP exam results for {identifier_value}")
            STEP_response = call_qiyas_soap_service(
                endpoint_url=soap_endpoint,
                action=soap_action,
                identifier_type="NationalID",
                identifier_value=identifier_value,
                exam_code=exam_code,
                exam_specialty_code='01',
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
                logger.warning(f"STEPAPI: Error parsing STEP exam results - {str(e)}")
                STEP_result = {
                    "error": "Error processing STEP exam results",
                    "error_type": "parsing_error"
                }
            
            # Build final result
            result = {
                "STEP": STEP_result,
            }
            
            duration = time.time() - start_time
            if STEP_result and 'error' not in STEP_result:
                logger.info(
                    f"STEPAPI: Successfully processed {identifier_value} in {duration:.2f}s - Results found"
                )
            else:
                logger.info(
                    f"STEPAPI: Processed {identifier_value} in {duration:.2f}s - No results or error"
                )
            
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"STEPAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class BachelorEligibilityAPIView(APIView):
    """
    Bachelor Eligibility API endpoint that calls Banner database stored procedure.
    """

   

    def post(self, request):
        """
        Handle POST request to check bachelor eligibility using Banner stored procedure.
        """
        start_time = time.time()
        
        try:
            # Get SSN from query parameters
            ssn = request.data.get('identifier')
            
            if not ssn:
                logger.warning("BachelorEligibilityAPI: Missing identifier in request")
                return Response(
                    {"error": "identifier parameter is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate SSN format (should be 10 digits)
            if not ssn.isdigit() or len(ssn) != 10:
                logger.warning(f"BachelorEligibilityAPI: Invalid identifier format - {ssn} (must be 10 digits)")
                return Response(
                    {"error": "SSN must be exactly 10 digits"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            logger.info(f"BachelorEligibilityAPI: Checking bachelor eligibility for SSN: {ssn}")
            
            # Call Banner stored procedure
            # Import the Banner stored procedure utility function
            from .utils import execute_oracle_function
            
            # Call the stored procedure
            procedure_result = execute_oracle_function(
                function_name='QUERYADM.F_GET_ELIGIBILITY',
                parameters=[ssn]
            )
            
            if procedure_result["status"] == "success":
                duration = time.time() - start_time
                logger.info(
                    f"BachelorEligibilityAPI: Successfully checked eligibility for {ssn} in {duration:.2f}s - "
                    f"Result: {procedure_result['result']}"
                )
                result = {
                    "status": "success",
                    "ssn": ssn,
                    "eligibility_result": procedure_result["result"],
                    "message": "Bachelor eligibility checked successfully"
                }
            else:
                duration = time.time() - start_time
                logger.warning(
                    f"BachelorEligibilityAPI: Eligibility check failed for {ssn} in {duration:.2f}s - "
                    f"{procedure_result['error_message']}"
                )
                result = {
                    "status": "error",
                    "ssn": ssn,
                    "error_message": procedure_result["error_message"],
                    "error_type": procedure_result.get("error_type", "procedure_error")
                }
            
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"BachelorEligibilityAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class NationalAddressAPIView(APIView):
    """
    National Address API endpoint that integrates with Wasel Address SOAP service.
    """
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
                logger.warning("NationalAddressAPI: Missing Identifier in request")
                return Response(
                    {"error": "Identifier is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate Identifier format
            if not isinstance(identifier, str) or len(identifier.strip()) == 0:
                logger.warning(f"NationalAddressAPI: Invalid Identifier format - {identifier}")
                return Response(
                    {"error": "Identifier must be a non-empty string"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            identifier = identifier.strip()
            
            logger.info(f"NationalAddressAPI: Processing national address request for ID: {identifier}")
            
            # Call National Address SOAP service
            soap_endpoint = config('NATIONAL_ADDRESS_SOAP_ENDPOINT')
            soap_action = config('NATIONAL_ADDRESS_SOAP_ACTION')
            
            # Define custom headers for SOAP request
            custom_headers = {
                'Content-Type': 'text/xml;charset=UTF-8',
                'SOAPAction': soap_action,
                'Connection': 'Keep-Alive',
                'Accept-Encoding': 'gzip, deflate',
                'User-Agent': 'python-requests/2.25.1',
                'Accept': '*/*'
            }
            
            logger.debug(f"NationalAddressAPI: Calling SOAP service for {identifier}")
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
                        "data": {
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
                        },
                        "status": "success",
                        "message": "National address retrieved successfully"
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
            
            # Log based on success/failure
            duration = time.time() - start_time
            if result.get("status") == "success":
                logger.info(
                    f"NationalAddressAPI: Successfully retrieved address for {identifier} in {duration:.2f}s"
                )
            else:
                logger.warning(
                    f"NationalAddressAPI: Failed to retrieve address for {identifier} in {duration:.2f}s - "
                    f"{result.get('error', 'Unknown error')}"
                )
            
            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"NationalAddressAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




class StudentInfoAPIView(APIView):
   
    parser_classes = [JSONParser]
   
    def post(self, request):
        start_time = time.time()
        
        try:
            # Get parameters from request
            student_id = request.data.get('student_id')
            mobile = request.data.get('mobile', None)
            seu_email = request.data.get('seu_email', None)
            national_id = request.data.get('national_id', None)
            
            if not student_id and not mobile and not seu_email and not national_id:
                logger.warning("StudentInfoAPI: Missing all required parameters")
                return Response(
                    {"error": "Missing required parameters student_id, mobile, seu_email, or national_id"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate student_id format
            if student_id:
                if not student_id.isdigit() or len(student_id.strip()) != 9:
                    logger.warning(f"StudentInfoAPI: Invalid Student ID format - {student_id} (must be 9 digits)")
                    return Response(
                        {"error": "Student ID must be 9 digits with no characters"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                student_id = student_id.strip()
                
            # Validate mobile number format
            if mobile:
                if not mobile.isdigit() or len(mobile.strip()) != 12 or not mobile.strip().startswith('9665'):
                    logger.warning(f"StudentInfoAPI: Invalid mobile format - {mobile} (must be 12 digits starting with 9665)")
                    return Response(
                        {"error": "Mobile number must be 12 digits starting with 9665"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                mobile = mobile.strip() if mobile else None
            
            # Validate seu_email format
            if seu_email:
                import re
                email_pattern = r'^[a-zA-Z0-9._%+-]+@seu.edu.sa'
                if not re.match(email_pattern, seu_email.strip()):
                    logger.warning(f"StudentInfoAPI: Invalid email format - {seu_email}")
                    return Response(
                        {"error": "SEU Email must be a valid email"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                seu_email = seu_email.strip()

            # Validate national_id format
            if national_id:
                if not national_id.isdigit() or len(national_id.strip()) != 10:
                    logger.warning(f"StudentInfoAPI: Invalid National ID format - {national_id} (must be 10 digits)")
                    return Response(
                        {"error": "National ID must be 10 digits with no characters"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                national_id = national_id.strip()
            
            # Log the processing start
            search_param = student_id or mobile or seu_email or national_id
            logger.info(f"StudentInfoAPI: Processing request for: {search_param}")

          
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
            logger.debug(f"StudentInfoAPI: Calling stored procedure GET_STUDENT_INFO4")
            from .utils import execute_oracle_stored_procedure
            result = execute_oracle_stored_procedure(
                procedure_name='BANINST1.GET_STUDENT_INFO4',
                in_parameters=in_parameters,
                out_parameters=out_parameters
            )
            
            duration = time.time() - start_time
            
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
                
                logger.info(
                    f"StudentInfoAPI: Successfully retrieved student info for {search_param} in {duration:.2f}s"
                )
                return Response(result, status=status.HTTP_200_OK)
            else:
                logger.warning(
                    f"StudentInfoAPI: Failed to retrieve student info for {search_param} in {duration:.2f}s - "
                    f"{result.get('error_message', 'Unknown error')}"
                )
                return Response(result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"StudentInfoAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@method_decorator(csrf_exempt, name='dispatch')
class SMSAPIView(APIView):
   
    parser_classes = [JSONParser]  # Let DRF use default parsers
   
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            # Get parameters from request
            numbers = request.data.get('numbers')
            message = request.data.get('message')
            
            # Validate required parameters
            if not numbers:
                logger.warning("SMSAPI: Missing numbers parameter in request")
                return Response(
                    {"error": "Numbers parameter is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if not message:
                logger.warning("SMSAPI: Missing message parameter in request")
                return Response(
                    {"error": "Message parameter is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate and clean numbers
            if isinstance(numbers, str):
                # Split comma-separated numbers and clean them
                number_list = [num.strip() for num in numbers.split(',') if num.strip()]
                
                if not number_list:
                    logger.warning("SMSAPI: No valid phone numbers provided")
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
                    logger.warning(f"SMSAPI: {error_msg}")
                    return Response(
                        {"error": error_msg}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
            
            # Validate message length
            if len(message.strip()) == 0:
                logger.warning("SMSAPI: Empty message provided")
                return Response(
                    {"error": "Message cannot be empty"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if len(message) > 1600:  # SMS length limit
                logger.warning(f"SMSAPI: Message too long ({len(message)} characters, max 1600)")
                return Response(
                    {"error": "Message too long (max 1600 characters)"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Log the processing start
            recipient_count = len(numbers.split(','))
            logger.info(f"SMSAPI: Sending SMS to {recipient_count} recipient(s)")
            
            # Send SMS
            response_data = self.send_sms(numbers, message)
            
            duration = time.time() - start_time
            if response_data.get('status') == 'success':
                logger.info(
                    f"SMSAPI: Successfully sent SMS to {recipient_count} recipient(s) in {duration:.2f}s"
                )
            else:
                logger.warning(
                    f"SMSAPI: Failed to send SMS in {duration:.2f}s - {response_data.get('error', 'Unknown error')}"
                )
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"SMSAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
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

        logger.debug(f"SMSAPI: Calling SMS gateway for {len(numbers.split(','))} recipient(s)")

        try:
            # Make the POST request
            response = requests.post(url, headers=headers, json=payload)

            # Raise an HTTPError for bad responses (4xx or 5xx)
            response.raise_for_status()

            # Parse the JSON response
            response_data = response.json()
            
            # Standardize response format
            if response_data.get('code') == '1':
                logger.debug(f"SMSAPI: SMS gateway returned success code")
                return {
                    "status": "success",
                    "message": "SMS sent successfully",
                    "numbers_count": len(numbers.split(',')),
                    "numbers": numbers,
                    "api_response": response_data
                }
            else:
                error_msg = response_data.get('message', 'SMS sending failed')
                logger.warning(f"SMSAPI: SMS gateway returned error - {error_msg}")
                return {
                    "status": "error",
                    "error": error_msg,
                    "numbers": numbers,
                    "api_response": response_data
                }

        except requests.exceptions.HTTPError as http_err:
            logger.error(f"SMSAPI: HTTP error from SMS gateway - {http_err}", exc_info=True)
            return {"status": "error", "error": "HTTP Error", "details": str(http_err)}
        except requests.exceptions.ConnectionError as conn_err:
            logger.error(f"SMSAPI: Connection error to SMS gateway - {conn_err}")
            return {"status": "error", "error": "Connection Error", "details": str(conn_err)}
        except requests.exceptions.Timeout as timeout_err:
            logger.error(f"SMSAPI: Timeout error from SMS gateway - {timeout_err}")
            return {"status": "error", "error": "Timeout Error", "details": str(timeout_err)}
        except requests.exceptions.RequestException as req_err:
            logger.error(f"SMSAPI: Request error to SMS gateway - {req_err}", exc_info=True)
            return {"status": "error", "error": "Request Error", "details": str(req_err)}
        except json.JSONDecodeError as json_err:
            logger.error(f"SMSAPI: Failed to decode JSON response - {json_err}")
            return {"status": "error", "error": "JSON Decode Error", "details": str(json_err)}

@method_decorator(csrf_exempt, name='dispatch')
class StudentMobileAPIView(APIView):
   
    parser_classes = [JSONParser]  # Let DRF use default parsers
   
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            # Get parameters from request
            mobile = request.data.get('mobile')
            student_id = request.data.get('student_id')
            
            # Validate mobile number
            if mobile:
                if len(mobile.strip()) != 12 or not mobile.strip().isdigit() or not mobile.strip().startswith('9665'):
                    logger.warning(f"StudentMobileAPI: Invalid mobile format - {mobile} (must be 12 digits starting with 9665)")
                    return Response(
                        {"error": "Mobile number must be 12 digits and start with 9665"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                logger.warning("StudentMobileAPI: Missing mobile number in request")
                return Response(
                    {"error": "Mobile number is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate student ID
            if student_id:
                if len(student_id.strip()) != 9 or not student_id.strip().isdigit():
                    logger.warning(f"StudentMobileAPI: Invalid student ID format - {student_id} (must be 9 digits)")
                    return Response(
                        {"error": "Student ID must be 9 digits"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                logger.warning("StudentMobileAPI: Missing student ID in request")
                return Response(
                    {"error": "Student ID is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            logger.info(f"StudentMobileAPI: Updating mobile number for student ID: {student_id}")
            
            response_data = self.update_student_mobile(student_id, mobile)
            
            duration = time.time() - start_time
            if response_data.get('status') == 'success':
                logger.info(
                    f"StudentMobileAPI: Successfully updated mobile for student {student_id} in {duration:.2f}s"
                )
            else:
                logger.warning(
                    f"StudentMobileAPI: Failed to update mobile for student {student_id} in {duration:.2f}s - "
                    f"{response_data.get('message', 'Unknown error')}"
                )
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"StudentMobileAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    def update_student_mobile(self, student_id, mobile_number):
        """
        Update student contact info via stored procedure.
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
            
            logger.debug(f"StudentMobileAPI: Calling stored procedure update_student_mobile for student {student_id}")
            result = execute_oracle_stored_procedure(
                procedure_name='BANINST1.update_student_mobile',
                in_parameters=in_parameters,
                out_parameters=out_parameters
            )
            
            # Transform the result to match the expected format
            if result.get("status") == "success":
                output_params = result.get('output_parameters', {})
                status_msg = output_params.get('O_STATUS', 'Student mobile number updated successfully')
                logger.debug(f"StudentMobileAPI: Stored procedure returned success - {status_msg}")
                return {
                    "status": "success", 
                    "message": status_msg,
                    "student_id": student_id,
                    "mobile": mobile_number
                }
            else:
                error_msg = result.get('error_message', 'Error updating student mobile number')
                logger.warning(f"StudentMobileAPI: Stored procedure failed - {error_msg}")
                return {
                    "status": "error", 
                    "message": error_msg
                }

        except Exception as e:
            logger.error(f"StudentMobileAPI: Exception in update_student_mobile - {str(e)}", exc_info=True)
            return {"status": "error", "message": "Error updating student mobile number"}



# ERP api points


class EmployeeProfileAPIView(APIView):
    parser_classes = [JSONParser]

    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("EmployeeProfileAPI: Processing employee profile request")
            
            url = config('ERP_GATEWAY_URL') + 'webservices/rest/XXX_SERVNOW_INTEG_API/get_emp_profile/'
            username = config('ERP_GATEWAY_USERNAME')
            password = config('ERP_GATEWAY_PASSWORD')

            headers = {
                "Content-Type": "application/json"
            }
            
            logger.debug(f"EmployeeProfileAPI: Calling ERP gateway at {url}")
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            
            duration = time.time() - start_time
            if response.status_code == 200:
                logger.info(f"EmployeeProfileAPI: Successfully retrieved employee profile in {duration:.2f}s")
            else:
                logger.warning(
                    f"EmployeeProfileAPI: ERP gateway returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response.json(), status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"EmployeeProfileAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
#For Ejadah ERP...
#SPM endpoints
class PRCreateAPIView(APIView):
    parser_classes = [JSONParser]
    
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("PRCreateAPI: Processing purchase requisition creation request")
            
            url = config('EJADAH_ERP_URL') + '/webservices/rest/XXX_SPM_INTEG_API/create_purchase_requestion/'
            username = config('EJADAH_ERP_USERNAME')
            password = config('EJADAH_ERP_PASSWORD')
            
            headers = {
                "Content-Type": "application/json"
            }
            
            logger.debug(f"PRCreateAPI: Calling Ejadah ERP at {url}")
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            
            duration = time.time() - start_time
            if response.status_code == 200:
                logger.info(f"PRCreateAPI: Successfully created purchase requisition in {duration:.2f}s")
            else:
                logger.warning(
                    f"PRCreateAPI: Ejadah ERP returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response.json(), status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"PRCreateAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PRRequestDetailsAPIView(APIView):
    parser_classes = [JSONParser]
   
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("PRRequestDetailsAPI: Processing purchase requisition details request")
            
            url = config('EJADAH_ERP_URL') + '/webservices/rest/XX_SPM_GET_PR/get_purchase_requestion/'
            username = config('EJADAH_ERP_USERNAME')
            password = config('EJADAH_ERP_PASSWORD')
            
            headers = {
                "Content-Type": "application/json"
            }
            
            logger.debug(f"PRRequestDetailsAPI: Calling Ejadah ERP at {url}")
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            
            duration = time.time() - start_time
            if response.status_code == 200:
                logger.info(f"PRRequestDetailsAPI: Successfully retrieved PR details in {duration:.2f}s")
            else:
                logger.warning(
                    f"PRRequestDetailsAPI: Ejadah ERP returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response.json(), status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"PRRequestDetailsAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class PRAttachementAPIView(APIView):
    parser_classes = [JSONParser]

    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("PRAttachementAPI: Processing PR file attachment request")
            
            url = config('EJADAH_ERP_URL') + '/webservices/rest/XX_ATTCH_FILE_PR_WEBSERVICES/add_pr_file_attachment/'
            username = config('EJADAH_ERP_USERNAME')
            password = config('EJADAH_ERP_PASSWORD')
            
            headers = {
                "Content-Type": "application/json"
            }
            
            logger.debug(f"PRAttachementAPI: Calling Ejadah ERP at {url}")
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            
            duration = time.time() - start_time
            if response.status_code == 200:
                logger.info(f"PRAttachementAPI: Successfully added PR attachment in {duration:.2f}s")
            else:
                logger.warning(
                    f"PRAttachementAPI: Ejadah ERP returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response.json(), status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"PRAttachementAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class PRCancelAPIView(APIView):
    parser_classes = [JSONParser]

    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("PRCancelAPI: Processing PR cancellation request")
            
            url = config('EJADAH_ERP_URL') + '/webservices/rest/XXX_SPM_INTEG_API/cancel_purchase_requestion/'
            username = config('EJADAH_ERP_USERNAME')
            password = config('EJADAH_ERP_PASSWORD')
            
            headers = {
                "Content-Type": "application/json"
            }
            
            logger.debug(f"PRCancelAPI: Calling Ejadah ERP at {url}")
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            
            duration = time.time() - start_time
            if response.status_code == 200:
                logger.info(f"PRCancelAPI: Successfully cancelled PR in {duration:.2f}s")
            else:
                logger.warning(
                    f"PRCancelAPI: Ejadah ERP returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response.json(), status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"PRCancelAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class PRWorkConfirmationCreateAPIView(APIView):
    parser_classes = [JSONParser]

    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("PRWorkConfirmationCreateAPI: Processing work confirmation creation request")
            
            url = config('EJADAH_ERP_URL') + '/webservices/rest/XXX_SPM_INTEG_API/create_work_confirmation/'
            username = config('EJADAH_ERP_USERNAME')
            password = config('EJADAH_ERP_PASSWORD')
            
            headers = {
                "Content-Type": "application/json"
            }
            
            logger.debug(f"PRWorkConfirmationCreateAPI: Calling Ejadah ERP at {url}")
            response = requests.post(url, headers=headers, json=request.data, auth=(username, password))
            
            duration = time.time() - start_time
            if response.status_code == 200:
                logger.info(f"PRWorkConfirmationCreateAPI: Successfully created work confirmation in {duration:.2f}s")
            else:
                logger.warning(
                    f"PRWorkConfirmationCreateAPI: Ejadah ERP returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response.json(), status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"PRWorkConfirmationCreateAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class StudentProfileAPIView(APIView):
    """
    Student Info by Mobile API endpoint that calls Oracle stored procedure to get student information by mobile number.
    """
    parser_classes = [JSONParser]

    def post(self, request):
        start_time = time.time()
        
        try:
            seu_email = request.data.get('email', None)

            if not seu_email:
                logger.warning("StudentProfileAPI: Missing student email in request")
                return Response(
                    {"error": "Student email is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate email format
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, seu_email.strip()):
                logger.warning(f"StudentProfileAPI: Invalid email format - {seu_email}")
                return Response(
                    {"error": "SEU Email must be a valid email"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            seu_email = seu_email.strip()
            
            logger.info(f"StudentProfileAPI: Retrieving student profile for email: {seu_email}")

            # Prepare IN parameters
            from collections import OrderedDict
            in_parameters = OrderedDict([
                ('p_seu_email', seu_email),
            ])
             
            # Prepare OUT parameters
            out_parameters = [
                'o_result',
                'o_result_msg',
            ]
            
            # Call the stored procedure
            logger.debug(f"StudentProfileAPI: Calling stored procedure GET_STUDENT_profile")
            from .utils import execute_oracle_stored_procedure
            result = execute_oracle_stored_procedure(
                procedure_name='BANINST1.GET_STUDENT_profile',
                in_parameters=in_parameters,
                out_parameters=out_parameters
            )
            
            duration = time.time() - start_time
            
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
                
                logger.info(
                    f"StudentProfileAPI: Successfully retrieved profile for {seu_email} in {duration:.2f}s"
                )
            else:
                logger.warning(
                    f"StudentProfileAPI: Failed to retrieve profile for {seu_email} in {duration:.2f}s - "
                    f"{result.get('error_message', 'Unknown error')}"
                )

            return Response(result, status=status.HTTP_200_OK)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"StudentProfileAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ATSGenerateSeqReportAPIView(APIView):
    parser_classes = [JSONParser]

    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("ATSGenerateSeqReportAPI: Processing generate seq report request")
            
            url = config('ATS_ERP_PROD_GATEWAY_URL') + '/seu/services/v1/generate/seq/report'
            logger.debug(f"ATSGenerateSeqReportAPI: Calling ATS ERP at {url}")
            
            response = requests.post(
                url, 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
            duration = time.time() - start_time
            response_data = response.json()
            
            if response.status_code == 200:
                logger.info(f"ATSGenerateSeqReportAPI: Successfully generated seq report in {duration:.2f}s")
            else:
                logger.warning(
                    f"ATSGenerateSeqReportAPI: ATS ERP returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response_data, status=response.status_code)
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"ATSGenerateSeqReportAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class ATSCreateReportAPIView(APIView):
    parser_classes = [JSONParser]
   
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("ATSCreateReportAPI: Processing create report request")
            
            url = config('ATS_ERP_PROD_GATEWAY_URL') + '/seu/services/v1/getlookupreports'
            logger.debug(f"ATSCreateReportAPI: Calling ATS ERP at {url}")
            
            response = requests.post(
                url, 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
            duration = time.time() - start_time
            response_data = response.json()
            
            if response.status_code == 200:
                logger.info(f"ATSCreateReportAPI: Successfully created report in {duration:.2f}s")
            else:
                logger.warning(
                    f"ATSCreateReportAPI: ATS ERP returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response_data, status=response.status_code)

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"ATSCreateReportAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ATSShowReportAPIView(APIView):
    parser_classes = [JSONParser]
      
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("ATSShowReportAPI: Processing show report request")
            
            url = config('ATS_ERP_PROD_GATEWAY_URL') + '/seu/services/v1/show/report'
            logger.debug(f"ATSShowReportAPI: Calling ATS ERP at {url}")
            
            response = requests.get(
                url, 
                headers=dict(request.headers), 
                params=request.data,  # Use params for GET request instead of json
                timeout=30
            )
            
            duration = time.time() - start_time
            
            if response.status_code == 200:
                logger.info(f"ATSShowReportAPI: Successfully retrieved report PDF in {duration:.2f}s")
                pdf_response = HttpResponse(
                    response.content, 
                    content_type='application/pdf'
                )
                pdf_response['Content-Disposition'] = 'attachment; filename="report.pdf"'
                return pdf_response
            else:
                logger.warning(
                    f"ATSShowReportAPI: ATS ERP returned status {response.status_code} in {duration:.2f}s"
                )
                return Response(
                    {"error": f"Failed to retrieve report, status: {response.status_code}"}, 
                    status=response.status_code
                )
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"ATSShowReportAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# 

class ATSLeaveTypesAPIView(APIView):
    parser_classes = [JSONParser]
   
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("ATSLeaveTypesAPI: Processing leave types request")
            
            url = config('ATS_ERP_TEST_GATEWAY_URL') + '/ords/services/v1/getlookupvac'
            logger.debug(f"ATSLeaveTypesAPI: Calling ATS ERP at {url}")
            
            response = requests.post(
                url, 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
            duration = time.time() - start_time
            response_data = response.json()
            
            if response.status_code == 200:
                logger.info(f"ATSLeaveTypesAPI: Successfully retrieved leave types in {duration:.2f}s")
            else:
                logger.warning(
                    f"ATSLeaveTypesAPI: ATS ERP returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response_data, status=response.status_code)

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"ATSLeaveTypesAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class ATSLeaveBalanceAPIView(APIView):
    parser_classes = [JSONParser]
 
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("ATSLeaveBalanceAPI: Processing leave balance request")
            
            url = config('ATS_ERP_TEST_GATEWAY_URL') + '/ords/services/v1/getbalance'
            logger.debug(f"ATSLeaveBalanceAPI: Calling ATS ERP at {url}")
            
            response = requests.post(
                url, 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
            duration = time.time() - start_time
            response_data = response.json()
            
            if response.status_code == 200:
                logger.info(f"ATSLeaveBalanceAPI: Successfully retrieved leave balance in {duration:.2f}s")
            else:
                logger.warning(
                    f"ATSLeaveBalanceAPI: ATS ERP returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response_data, status=response.status_code)

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"ATSLeaveBalanceAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class ATSLeaveWorkflowDetailsAPIView(APIView):
    parser_classes = [JSONParser]
   
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("ATSLeaveWorkflowDetailsAPI: Processing leave workflow details request")
            
            url = config('ATS_ERP_TEST_GATEWAY_URL') + '/ords/services/v1/order/vac/det/emp'
            logger.debug(f"ATSLeaveWorkflowDetailsAPI: Calling ATS ERP at {url}")
            
            response = requests.post(
                url, 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
            duration = time.time() - start_time
            response_data = response.json()
            
            if response.status_code == 200:
                logger.info(f"ATSLeaveWorkflowDetailsAPI: Successfully retrieved workflow details in {duration:.2f}s")
            else:
                logger.warning(
                    f"ATSLeaveWorkflowDetailsAPI: ATS ERP returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response_data, status=response.status_code)

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"ATSLeaveWorkflowDetailsAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            



class ATSSubstitutesAPIView(APIView):
    parser_classes = [JSONParser]
   
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("ATSSubstitutesAPI: Processing substitutes request")
            
            url = config('ATS_ERP_TEST_GATEWAY_URL') + '/ords/services/v1/get/replacementEmployees'
            logger.debug(f"ATSSubstitutesAPI: Calling ATS ERP at {url}")
            
            response = requests.post(
                url, 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
            duration = time.time() - start_time
            response_data = response.json()
            
            if response.status_code == 200:
                logger.info(f"ATSSubstitutesAPI: Successfully retrieved substitutes in {duration:.2f}s")
            else:
                logger.warning(
                    f"ATSSubstitutesAPI: ATS ERP returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response_data, status=response.status_code)

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"ATSSubstitutesAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            


class ATSRequestEServiceAPIView(APIView):
    parser_classes = [JSONParser]
   
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("ATSRequestEServiceAPI: Processing eService request")
            
            url = config('ATS_ERP_TEST_GATEWAY_URL') + '/ords/services/v1/vac/requst'
            logger.debug(f"ATSRequestEServiceAPI: Calling ATS ERP at {url}")
            
            response = requests.post(
                url, 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
            duration = time.time() - start_time
            response_data = response.json()
            
            if response.status_code == 200:
                logger.info(f"ATSRequestEServiceAPI: Successfully processed eService request in {duration:.2f}s")
            else:
                logger.warning(
                    f"ATSRequestEServiceAPI: ATS ERP returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response_data, status=response.status_code)

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"ATSRequestEServiceAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            




class ATSRequestCancelAPIView(APIView):
    parser_classes = [JSONParser]
   
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("ATSRequestCancelAPI: Processing leave cancellation request")
            
            url = config('ATS_ERP_TEST_GATEWAY_URL') + '/ords/services/v1/vac/cancelEmpLeave'
            logger.debug(f"ATSRequestCancelAPI: Calling ATS ERP at {url}")
            
            response = requests.post(
                url, 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
            duration = time.time() - start_time
            response_data = response.json()
            
            if response.status_code == 200:
                logger.info(f"ATSRequestCancelAPI: Successfully cancelled leave in {duration:.2f}s")
            else:
                logger.warning(
                    f"ATSRequestCancelAPI: ATS ERP returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response_data, status=response.status_code)

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"ATSRequestCancelAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )





class ATSLeaveWorkflowStatusAPIView(APIView):
    parser_classes = [JSONParser]
   
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        
        try:
            logger.info("ATSLeaveWorkflowStatusAPI: Processing workflow status request")
            
            url = config('ATS_ERP_TEST_GATEWAY_URL') + '/ords/services/v1/vac/getworkflow/emp'
            logger.debug(f"ATSLeaveWorkflowStatusAPI: Calling ATS ERP at {url}")
            
            response = requests.post(
                url, 
                headers=dict(request.headers), 
                json=request.data,
                timeout=30
            )
            
            duration = time.time() - start_time
            response_data = response.json()
            
            if response.status_code == 200:
                logger.info(f"ATSLeaveWorkflowStatusAPI: Successfully retrieved workflow status in {duration:.2f}s")
            else:
                logger.warning(
                    f"ATSLeaveWorkflowStatusAPI: ATS ERP returned status {response.status_code} in {duration:.2f}s"
                )
            
            return Response(response_data, status=response.status_code)
  
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"ATSLeaveWorkflowStatusAPI: Exception after {duration:.2f}s - {str(e)}",
                exc_info=True
            )
            return Response(
                {"error": "Internal server error"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# New views from seu_tools_views.py



class ATSGetInfoOptimized(APIView):
    
    parser_classes = [JSONParser]
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


class ATSGetInfoOptimizedProduction(APIView):
   
    parser_classes = [JSONParser]
   
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


class StudentTranscriptAPIView(APIView):
    """
    Student Transcript API endpoint that calls Oracle stored procedure to get student transcript by student ID.
    """
   
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
  
    parser_classes = [JSONParser]

    
   
    def post(self, request):
        """
        Handle POST request to get student schedule by student ID.
        """
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


class BannerCampusesAPIView(APIView):
    """
    Student Schedule API endpoint that calls Oracle stored procedure to get student schedule by student ID.
    """
   
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
  
    parser_classes = [ JSONParser]

    
   
    def post(self, request):
        """
        Handle POST request to get student schedule by student ID.
        """
       
        start_time = time.time()
        
        try:

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

            return Response(json.loads(result.get('output_parameters', {}).get('o_json')), status=status.HTTP_200_OK)
        
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


# Helper function for ShowReportAPIView
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


class ShowReportTypesAPIView(APIView):
   
    parser_classes = [JSONParser]
   
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


class ShowReportAPIView(APIView):
    parser_classes = [JSONParser]
   
   
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


            