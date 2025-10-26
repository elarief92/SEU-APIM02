"""
Certificate processing utilities for the SEU Tools APIs.
Contains functions for extracting subscription months from GOSI certificates.
"""

import json
import time
import base64
import math

import requests
# Import handling for optional dependencies
try:
    import magic
    import pdf2image
    import pdfplumber
    from PIL import Image
    from openai import AzureOpenAI
except ImportError:
    # These are optional dependencies for PDF processing
    magic = None
    pdf2image = None
    pdfplumber = None
    Image = None
    AzureOpenAI = None

import io
import re
import os
import logging
from typing import Dict, Optional
from django.http import HttpResponse
from django.conf import settings
from decouple import config
import json

# Handle pyodbc for Oracle/SQL Server connections
try:
    import pyodbc
except ImportError:
    pyodbc = None


# Set up Oracle environment variables at module level for Windows
if os.name == 'nt':  # Windows
    os.environ['ORACLE_HOME'] = r'C:\oracle\instantclient_23_8'
    if r'C:\oracle\instantclient_23_8' not in os.environ.get('PATH', ''):
        os.environ['PATH'] = os.environ['PATH'] + r';C:\oracle\instantclient_23_8'

# Set up processing logger
#logger = logging.getLogger('processing')

def get_requester_name(request):
    """Get the requester name from the request - returns default since auth is removed."""
    # Return default name since authentication is removed
    return 'API User'

def extract_subscription_months_from_pdf(file_content: bytes, filename: str) -> Dict[str, str]:
    """
    Extract total subscription months from a certificate PDF using text extraction.
    
    This function processes both Arabic and English GOSI certificates to extract
    the total subscription months value. It uses direct PDF text extraction
    and supports both formats:
    - Arabic: Looks for "ﺮﻬﺷ" pattern
    - English: Looks for numbers followed by "Months"
    
    Parameters:
    ----------
    file_content : bytes
        The PDF file content
    filename : str
        The name of the uploaded file
    
    Returns:
    -------
    Dict[str, str]
        A dictionary containing:
        - status: "success" or "error"
        - subscription_months: The extracted number of months (if successful) or NA
        - subscription_years: The equivalent in years (if successful) or NA
        - mock: Whether the result is a mock or not (if successful)
            - error_message: Error details (if failed)
            - debug_text: Debug information (if failed)
    
    """
    try:
        # Open PDF with pdfplumber
        with pdfplumber.open(io.BytesIO(file_content)) as pdf:
            # Get the first page
            page = pdf.pages[0]
            
            # Extract text with layout preservation
            text = page.extract_text()
            lines = text.split('\n')
            
            debug_text = []
            subscription_months = None
            
            # Search for the target text and extract the number
            for i, line in enumerate(lines):
                debug_text.append(f"Line {i}: {line}")
                
                # Try Arabic format first
                if "ﺮﻬﺷ" in line:
                    # Split by "ﺮﻬﺷ" to get all numbers
                    parts = line.split("ﺮﻬﺷ")
                    numbers = []
                    for part in parts:
                        nums = re.findall(r'\d+', part)
                        if nums:
                            numbers.extend(nums)
                    
                    # Find the largest number (which should be the total)
                    if numbers:
                        largest_num = max(int(num) for num in numbers)
                        subscription_months = str(largest_num)
                        break
                
                # Try English format
                elif "Months" in line:
                    # Extract all numbers followed by "Months"
                    numbers = re.findall(r'(\d+)\s*Months', line)
                    if numbers:
                        # Find the largest number (which should be the total)
                        largest_num = max(int(num) for num in numbers)
                        subscription_months = str(largest_num)
                        break
            
            if subscription_months:
              
                return {
                    "status": "success",
                    "subscription_months": subscription_months,
                    "subscription_years": math.floor(int(subscription_months) / 12),
                    "SSN": extract_SSN_from_pdf(file_content, filename),
                    #"QR_URL": extract_url_from_qr(file_content, filename),
                    "mock": False
                }
            else:
                return {
                    "status": "success",
                    "error_message": "Could not find subscription months information in the document",
                    "subscription_months": "NA",
                    "subscription_years": "NA",
                    "SSN": "NA",
                    "mock": False,
                }
    
    except Exception as e:
        #logger.error(f"Error processing certificate {filename}: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Error processing PDF: {str(e)}"
        }

def extract_SSN_from_pdf(file_content: bytes, filename: str) -> Dict[str, str]:
    """
    Extract SSN from a certificate PDF using text extraction.
    
    This function processes both Arabic and English GOSI certificates to extract
    the SSN value. It uses direct PDF text extraction
    and supports both formats:
    - Arabic: Looks for "رقم الهوية الوطنية/الإقامة" pattern
    - English: Looks for "National ID/IQAMAH" pattern
    
    Parameters:
    ----------
    file_content : bytes
        The PDF file content
    filename : str
        The name of the uploaded file
    
    Returns:
    -------
    str
        The extracted SSN value
    """
    try:
        # Open PDF with pdfplumber
        with pdfplumber.open(io.BytesIO(file_content)) as pdf:
            # Get the first page
            page = pdf.pages[0]

            lookup_text = ["ﺔﻣﺎﻗﻹﺍ / ﺔﻴﻨﻃﻮﻟﺍ ﺔﻳﻮﻬﻟﺍ ﻢﻗﺭ", "National ID/IQAMAH"]
            
            # Extract text with layout preservation
            text = page.extract_text()
            lines = text.split('\n')
            
            debug_text = []
            SSN = None
            SSN = lines[7].split(" ")[0]
            #English version
            if SSN.isdigit() and len(SSN) == 10:
               
                return SSN
            else:
               SSN= lines[6].split(" ")[2]
               if SSN.isdigit() and len(SSN) == 10:
                 
                   return SSN
               else:
                   return "SSN not found"
            
            
    
    except Exception as e:
        #logger.error(f"Error processing certificate {filename}: {str(e)}")
        return "SSN not found"

def process_pdf_with_ai(client: AzureOpenAI, file_content: bytes, filename: str, content_type: str) -> str:
    """Process PDF file by converting first page to image and using vision model."""
    try:
        # Convert first page of PDF to image
        images = pdf2image.convert_from_bytes(file_content, first_page=1, last_page=1)
        
        if not images:
            raise ValueError("Could not convert PDF to image")
        
        # Get the first (and only) page
        first_page = images[0]
        
        # Convert PIL Image to bytes
        img_byte_arr = io.BytesIO()
        first_page.save(img_byte_arr, format='PNG')
        image_bytes = img_byte_arr.getvalue()
        
        ai_response = process_image_with_ai(client, image_bytes, "image/png")
        
        return ai_response
        
        
    except Exception as e:
        error_msg = str(e)
        
        # Provide specific error message for Poppler issues
        if "poppler" in error_msg.lower() or "unable to get page count" in error_msg.lower():
            detailed_msg = ("PDF processing requires Poppler to be installed. "
                          "Please contact the system administrator to install Poppler-utils. "
                          f"Technical details: {error_msg}")
        else:
            detailed_msg = f"Could not process PDF: {error_msg}"
            
        raise ValueError(detailed_msg)

def process_image_with_ai(client: AzureOpenAI, file_content: bytes, file_type: str) -> str:
    """Process image file using Azure OpenAI Chat Completions API with vision."""
    try:
        base64_image = base64.b64encode(file_content).decode('utf-8')
        
        model_name = config("AZURE_OPEN_AI_MODEL_NAME", default="")
        if not model_name:
            raise ValueError("Missing AZURE_OPEN_AI_MODEL_NAME configuration")
        
        response = client.chat.completions.create(
        model=model_name,
        messages=[
            {
                "role": "system",
                "content": """You are an AI assistant specialized in analyzing GOSI certificates. 
                Your task is to extract the total subscription months (إجمالي أشهر الإشتراك or Total Subscription Months) 
                    and calculate the equivalent in years. also extract the (National ID / IQAMAH or رقم الهوية / الإقامة) from the certificate.
                Respond only in valid JSON format with two fields:
                - subscription_months: the exact number of months
                    - subscription_years: the equivalent in years (rounded)
                    - SSN: the National ID / IQAMAH (if found)
                    - QR_URL: the URL from the QR code in the certificate.
                    - mock: whether the result is a mock or not (if successful)
                    """
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Please analyze this GOSI certificate image and extract the total subscription months,years, the National ID / IQAMAH. Return only a JSON response."
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:{file_type};base64,{base64_image}"
                        }
                    }
                ]
            }
        ],
        max_tokens=800,
        temperature=1.0,
        top_p=1.0,
        frequency_penalty=0.0,
        presence_penalty=0.0,
    )
        
        return response.choices[0].message.content
        
    except Exception as e:
        raise ValueError(f"Azure OpenAI API call failed: {str(e)}")

def parse_ai_response(ai_response: str) -> Dict[str, str]:
    """Parse AI response and extract subscription months and years."""
    ##logger.debug(f"AI Response: {ai_response}")
    
    try:
        # Extract JSON from the response (it might be wrapped in ```json blocks)
        json_match = re.search(r'```json\s*(\{.*?\})\s*```', ai_response, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            json_str = ai_response
        
        response_json = json.loads(json_str)
        # Recalculate subscription_years using math.floor for consistency
        subscription_months = int(response_json['subscription_months'])
        subscription_years = math.floor(subscription_months / 12)
        
        if int(response_json['subscription_months']) > 0:
            return {
                "status": "success",
                "subscription_months": str(response_json['subscription_months']) ,
                "subscription_years": str(subscription_years) ,
                "SSN": response_json.get('SSN', 'NA'),
                "mock": response_json.get('mock', False)
            }
        else:
            return {
                "status": "success",
                "error_message": "Could not find subscription months information in the document",
                "subscription_months": "NA",
                "subscription_years": "NA",
                "SSN": "NA",
                "mock": False,
            }
    except (json.JSONDecodeError, KeyError) as e:
        ##logger.error(f"Error parsing AI response: {str(e)}")
        raise ValueError(f"Could not parse AI response: {ai_response}")

def extract_subscription_months_with_ai(file_content: bytes, filename: str, content_type: str) -> Dict[str, str]:
    """
    Extract total subscription months from a certificate using AI analysis.
    
    This function processes both PDF and image files using Azure OpenAI's vision model
    to extract subscription months information from GOSI certificates.
    
    Parameters:
    ----------
    file_content : bytes
        The file content (PDF or image)
    filename : str
        The name of the uploaded file
    content_type : str
        The MIME type of the file
    
    Returns:
    -------
    Dict[str, str]
        A dictionary containing:
        - status: "success" or "error"
        - subscription_months: The extracted number of months (if successful)
        - subscription_years: The equivalent in years (if successful)
        - mock: Whether the result is a mock or not (if successful)
            - error_message: Error details (if failed)
            - debug_text: Debug information (if failed)
        - error_message: Error details (if failed)
    """
    try:
        # Initialize Azure OpenAI client
        azure_endpoint = config("AZURE_OPEN_AI_ENDPOINT", default="")
        azure_key = config("AZURE_OPEN_AI_KEY", default="")
        azure_version = config("AZURE_OPEN_AI_API_VERSION", default="")
        
        if not azure_endpoint or not azure_key or not azure_version:
            missing_configs = []
            if not azure_endpoint: missing_configs.append("AZURE_OPEN_AI_ENDPOINT")
            if not azure_key: missing_configs.append("AZURE_OPEN_AI_KEY")
            if not azure_version: missing_configs.append("AZURE_OPEN_AI_API_VERSION")
            
            error_msg = f"Missing Azure OpenAI configuration: {', '.join(missing_configs)}"
            return {
                "status": "error",
                "error_message": error_msg
            }
        
        client = AzureOpenAI(
            azure_endpoint=azure_endpoint,
            api_key=azure_key,
            api_version=azure_version
        )
        
        # Detect file type
        file_type = magic.from_buffer(file_content, mime=True)
        ##logger.info(f"Detected file type: {file_type}")
        
        # Process based on file type
        if file_type == "application/pdf":
            ai_response = process_pdf_with_ai(client, file_content, filename, content_type)
        elif file_type.startswith("image/"):
            ai_response = process_image_with_ai(client, file_content, file_type)
        else:
            return {
                "status": "error",
                "error_message": f"Unsupported file type: {file_type}. Please upload a PDF or image file."
            }
        
        # Parse and return the response
        result = parse_ai_response(ai_response)
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "error_message": str(e)
        } 


def call_noor_soap_service(endpoint_url, action, student_identifier, headers=None):

    try:
        # Default SOAP headers matching Noor service requirements
        default_headers = {
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': action
        }
        
        # Merge with custom headers if provided
        if headers:
            default_headers.update(headers)
        
        # Build SOAP envelope based on Noor service requirements
        soap_envelope = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
                    <soapenv:Header/>
                    <soapenv:Body>
                        <tem:GetLastSchoolCertificate>
                            <tem:StudentIdentifier>{student_identifier}</tem:StudentIdentifier>
                        </tem:GetLastSchoolCertificate>
                    </soapenv:Body>
                    </soapenv:Envelope>"""
        
        # Log the request for debugging
        # ##logger.info(f"Calling Noor SOAP service: {endpoint_url}")
        # ##logger.info(f"Action: {action}")
        # ##logger.info(f"StudentIdentifier: {student_identifier}")
        
        # Make the SOAP request
        response = requests.post(
            endpoint_url,
            data=soap_envelope,
            headers=default_headers,
            timeout=30  # 30-second timeout
        )
        
        # Check for HTTP errors
        response.raise_for_status()
        
        # Parse the SOAP response
        response_data = {
            "status": "success",
            "soap_response": response.text,
            "status_code": response.status_code,
            "headers": dict(response.headers)
        }
        
        ##logger.info(f"Noor SOAP service response received successfully")
        return response_data
        
    except requests.exceptions.Timeout:
        error_msg = "SOAP service request timed out"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "timeout"
        }
        
    except requests.exceptions.ConnectionError:
        error_msg = "Failed to connect to SOAP service"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "connection_error"
        }
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP error from SOAP service: {e.response.status_code}"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "http_error",
            "status_code": e.response.status_code
        }
        
    except Exception as e:
        error_msg = f"Unexpected error calling SOAP service: {str(e)}"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "unexpected_error"
        }


def parse_noor_soap_response(soap_response_xml):
    """
    Parse SOAP response from Noor service and extract structured student information.
    Returns response in GetHighSchoolCertificateResponse format.
    
    Args:
        soap_response_xml (str): Raw SOAP XML response from Noor service
    
    Returns:
        dict: Structured student information in GetHighSchoolCertificateResponse format
    """
    try:
        import xml.etree.ElementTree as ET
        
        # Parse the XML
        root = ET.fromstring(soap_response_xml)
        
        # Define namespaces used in the response
        namespaces = {
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'tempuri': 'http://tempuri.org/',
            'student': 'http://yefi.gov.sa/MOE/SchoolStudentRecord/xml/schemas/version4.0',
            'person': 'http://yefi.gov.sa/PersonProfileCommonTypes/xml/schemas/version2.0',
            'common': 'http://yefi.gov.sa/CommonTypes/xml/schemas/version2.0'
        }
        
        # Initialize the response structure
        response = {
            "GetHighSchoolCertificateResponse": {
                "GetHighSchoolCertificateResult": {
                    "getHighSchoolCertificateResponseDetailObject": {
                        "StudentBasicInfo": {},
                        "SchoolInfo": {},
                        "CertificationDetails": {},
                        "CoursesList": {"CourseDetails": []}
                    }
                }
            }
        }
        
        # Extract student basic information
        student_basic_info = {}
        student_info_elem = root.find('.//student:StudentBasicInfo', namespaces)
        
        if student_info_elem is not None:
            # Student name in Arabic
            name_ar_elem = student_info_elem.find('.//person:PersonFullName', namespaces)
            if name_ar_elem is not None:
                student_basic_info['StudentNameAr'] = {
                    "@language": "AR",
                    "PersonFullName": name_ar_elem.text or ""
                }
            
            # Student name in English - find the second PersonFullName element
            name_elements = student_info_elem.findall('.//person:PersonFullName', namespaces)
            if len(name_elements) > 1:
                student_basic_info['StudentNameEn'] = {
                    "@language": "EN", 
                    "PersonFullName": name_elements[1].text or ""
                }
            
            # Gender
            gender_elem = student_info_elem.find('student:Gender', namespaces)
            if gender_elem is not None:
                student_basic_info['Gender'] = gender_elem.text or ""
            
            # Date of birth
            dob_greg_elem = student_info_elem.find('.//common:GregorianDate', namespaces)
            dob_hijri_elem = student_info_elem.find('.//common:HijriDate', namespaces)
            date_of_birth = {}
            if dob_greg_elem is not None:
                date_of_birth['GregorianDate'] = dob_greg_elem.text or ""
            if dob_hijri_elem is not None:
                date_of_birth['HijriDate'] = dob_hijri_elem.text or ""
            if date_of_birth:
                student_basic_info['DateOfBirth'] = date_of_birth
            
            # MOE Identifier
            moe_id_elem = student_info_elem.find('student:MoeIdentifier', namespaces)
            if moe_id_elem is not None:
                student_basic_info['MoeIdentifier'] = int(moe_id_elem.text) if moe_id_elem.text and moe_id_elem.text.isdigit() else moe_id_elem.text
            
            # MOE Identifier Type Description
            moe_type_elem = student_info_elem.find('student:MoeIdentifierTypeDesc', namespaces)
            if moe_type_elem is not None:
                student_basic_info['MoeIdentifierTypeDesc'] = moe_type_elem.text or ""
        
        # Extract school information
        school_info = {}
        school_info_elem = root.find('.//student:SchoolInfo', namespaces)
        
        if school_info_elem is not None:
            # School ID
            school_id_elem = school_info_elem.find('student:SchoolID', namespaces)
            if school_id_elem is not None:
                school_info['SchoolID'] = school_id_elem.text or ""
            
            # School names
            school_name_ar_elem = school_info_elem.find('student:SchoolNameAr', namespaces)
            school_name_en_elem = school_info_elem.find('student:SchoolNameEn', namespaces)
            if school_name_ar_elem is not None:
                school_info['SchoolNameAr'] = school_name_ar_elem.text or ""
            if school_name_en_elem is not None:
                school_info['SchoolNameEn'] = school_name_en_elem.text or ""
            
            # Education area
            edu_area_code_elem = school_info_elem.find('student:EducationAreaCode', namespaces)
            edu_area_name_ar_elem = school_info_elem.find('student:EducationAreaNameAr', namespaces)
            edu_area_name_en_elem = school_info_elem.find('student:EducationAreaNameEn', namespaces)
            if edu_area_code_elem is not None:
                school_info['EducationAreaCode'] = edu_area_code_elem.text or ""
            if edu_area_name_ar_elem is not None:
                school_info['EducationAreaNameAr'] = edu_area_name_ar_elem.text or ""
            if edu_area_name_en_elem is not None:
                school_info['EducationAreaNameEn'] = edu_area_name_en_elem.text
            
            # Administrative area
            admin_area_code_elem = school_info_elem.find('student:AdministrativeAreaCode', namespaces)
            admin_area_name_ar_elem = school_info_elem.find('student:AdministrativeAreaNameAr', namespaces)
            admin_area_name_en_elem = school_info_elem.find('student:AdministrativeAreaNameEn', namespaces)
            if admin_area_code_elem is not None:
                school_info['AdministrativeAreaCode'] = int(admin_area_code_elem.text) if admin_area_code_elem.text and admin_area_code_elem.text.isdigit() else admin_area_code_elem.text
            if admin_area_name_ar_elem is not None:
                school_info['AdministrativeAreaNameAr'] = admin_area_name_ar_elem.text or ""
            if admin_area_name_en_elem is not None:
                school_info['AdministrativeAreaNameEn'] = admin_area_name_en_elem.text
        
        # Extract certification details
        certification_details = {}
        cert_details_elem = root.find('.//student:CertificationDetails', namespaces)
        
        if cert_details_elem is not None:
            # Study type
            study_type_ar_elem = cert_details_elem.find('student:StudyTypeAr', namespaces)
            study_type_en_elem = cert_details_elem.find('student:StudyTypeEn', namespaces)
            if study_type_ar_elem is not None:
                certification_details['StudyTypeAr'] = study_type_ar_elem.text or ""
            if study_type_en_elem is not None:
                certification_details['StudyTypeEn'] = study_type_en_elem.text or ""
            
            # Educational level
            edu_level_elem = cert_details_elem.find('student:EducationalLevel', namespaces)
            if edu_level_elem is not None:
                certification_details['EducationalLevel'] = edu_level_elem.text or ""
            
            # Education type
            edu_type_ar_elem = cert_details_elem.find('student:EducationTypeAr', namespaces)
            edu_type_en_elem = cert_details_elem.find('student:EducationTypeEn', namespaces)
            if edu_type_ar_elem is not None:
                certification_details['EducationTypeAr'] = edu_type_ar_elem.text or ""
            if edu_type_en_elem is not None:
                certification_details['EducationTypeEn'] = edu_type_en_elem.text or ""
            
            # Major information
            major_code_elem = cert_details_elem.find('student:MajorCode', namespaces)
            major_type_ar_elem = cert_details_elem.find('student:MajorTypeAr', namespaces)
            major_type_en_elem = cert_details_elem.find('student:MajorTypeEn', namespaces)
            if major_code_elem is not None:
                certification_details['MajorCode'] = int(major_code_elem.text) if major_code_elem.text and major_code_elem.text.isdigit() else major_code_elem.text
            if major_type_ar_elem is not None:
                certification_details['MajorTypeAr'] = major_type_ar_elem.text or ""
            if major_type_en_elem is not None:
                certification_details['MajorTypeEn'] = major_type_en_elem.text or ""
            
            # GPA information
            gpa_elem = cert_details_elem.find('student:GPA', namespaces)
            gpa_type_ar_elem = cert_details_elem.find('student:GPATypeAr', namespaces)
            gpa_type_en_elem = cert_details_elem.find('student:GPATypeEn', namespaces)
            gpa_max_elem = cert_details_elem.find('student:GPAMAX', namespaces)
            gpa_degree_ar_elem = cert_details_elem.find('student:GPADegreeAr', namespaces)
            gpa_degree_en_elem = cert_details_elem.find('student:GPADegreeEn', namespaces)
            
            if gpa_elem is not None:
                try:
                    certification_details['GPA'] = float(gpa_elem.text) if gpa_elem.text else 0.0
                except ValueError:
                    certification_details['GPA'] = gpa_elem.text or ""
            if gpa_type_ar_elem is not None:
                certification_details['GPATypeAr'] = gpa_type_ar_elem.text or ""
            if gpa_type_en_elem is not None:
                certification_details['GPATypeEn'] = gpa_type_en_elem.text or ""
            if gpa_max_elem is not None:
                certification_details['GPAMAX'] = int(gpa_max_elem.text) if gpa_max_elem.text and gpa_max_elem.text.isdigit() else gpa_max_elem.text
            if gpa_degree_ar_elem is not None:
                certification_details['GPADegreeAr'] = gpa_degree_ar_elem.text or ""
            if gpa_degree_en_elem is not None:
                certification_details['GPADegreeEn'] = gpa_degree_en_elem.text or ""
            
            # Certification years
            cert_hijri_year_elem = cert_details_elem.find('student:CertificationHijriYear', namespaces)
            cert_greg_year_elem = cert_details_elem.find('student:CertificationGregYear', namespaces)
            if cert_hijri_year_elem is not None:
                certification_details['CertificationHijriYear'] = cert_hijri_year_elem.text or ""
            if cert_greg_year_elem is not None:
                certification_details['CertificationGregYear'] = cert_greg_year_elem.text or ""
            
            # Graduation date - find graduation date specifically (not DOB)
            grad_date_elems = cert_details_elem.findall('.//common:GregorianDate', namespaces)
            grad_hijri_elems = cert_details_elem.findall('.//common:HijriDate', namespaces)
            graduation_date = {}
            
            # Usually graduation date is different from DOB, get the last/appropriate one
            if grad_date_elems and len(grad_date_elems) > 0:
                graduation_date['GregorianDate'] = grad_date_elems[-1].text or ""
            if grad_hijri_elems and len(grad_hijri_elems) > 0:
                graduation_date['HijriDate'] = grad_hijri_elems[-1].text or ""
            if graduation_date:
                certification_details['GraduationDate'] = graduation_date
            
            # Class information
            class_code_elem = cert_details_elem.find('student:ClassCode', namespaces)
            class_type_ar_elem = cert_details_elem.find('student:ClassTypeAr', namespaces)
            class_type_en_elem = cert_details_elem.find('student:ClassTypeEn', namespaces)
            student_level_ar_elem = cert_details_elem.find('student:StudentLevelAr', namespaces)
            
            if class_code_elem is not None:
                certification_details['ClassCode'] = int(class_code_elem.text) if class_code_elem.text and class_code_elem.text.isdigit() else class_code_elem.text
            if class_type_ar_elem is not None:
                certification_details['ClassTypeAr'] = class_type_ar_elem.text or ""
            if class_type_en_elem is not None:
                certification_details['ClassTypeEn'] = class_type_en_elem.text or ""
            if student_level_ar_elem is not None:
                certification_details['StudentLevelAr'] = student_level_ar_elem.text or ""
        
        # Extract courses information
        courses_list = []
        courses_elem = root.find('.//student:CoursesList', namespaces)
        
        if courses_elem is not None:
            course_details = courses_elem.findall('student:CourseDetails', namespaces)
            
            for course in course_details:
                course_info = {}
                
                # Course code
                course_code_elem = course.find('student:CourseCode', namespaces)
                if course_code_elem is not None:
                    course_info['CourseCode'] = int(course_code_elem.text) if course_code_elem.text and course_code_elem.text.isdigit() else course_code_elem.text
                
                # Course names
                course_name_ar_elem = course.find('student:CourseNameAr', namespaces)
                course_name_en_elem = course.find('student:CourseNameEn', namespaces)
                if course_name_ar_elem is not None:
                    course_info['CourseNameAr'] = course_name_ar_elem.text or ""
                if course_name_en_elem is not None:
                    course_info['CourseNameEn'] = course_name_en_elem.text or ""
                
                # Course weight
                course_weight_elem = course.find('student:CourseWeight', namespaces)
                if course_weight_elem is not None:
                    course_info['CourseWeight'] = int(course_weight_elem.text) if course_weight_elem.text and course_weight_elem.text.isdigit() else course_weight_elem.text
                
                # Score information
                score_elem = course.find('student:Score', namespaces)
                max_score_elem = course.find('student:MaxScore', namespaces)
                score_type_ar_elem = course.find('student:ScoreTypeAr', namespaces)
                score_type_en_elem = course.find('student:ScoreTypeEn', namespaces)
                
                if score_elem is not None:
                    try:
                        course_info['Score'] = int(score_elem.text) if score_elem.text and score_elem.text.isdigit() else score_elem.text
                    except ValueError:
                        course_info['Score'] = score_elem.text or ""
                if max_score_elem is not None:
                    course_info['MaxScore'] = int(max_score_elem.text) if max_score_elem.text and max_score_elem.text.isdigit() else max_score_elem.text
                if score_type_ar_elem is not None:
                    course_info['ScoreTypeAr'] = score_type_ar_elem.text or ""
                if score_type_en_elem is not None:
                    course_info['ScoreTypeEn'] = score_type_en_elem.text or ""
                
                courses_list.append(course_info)
        
        # Populate the response structure
        response["GetHighSchoolCertificateResponse"]["GetHighSchoolCertificateResult"]["getHighSchoolCertificateResponseDetailObject"]["StudentBasicInfo"] = student_basic_info
        response["GetHighSchoolCertificateResponse"]["GetHighSchoolCertificateResult"]["getHighSchoolCertificateResponseDetailObject"]["SchoolInfo"] = school_info
        response["GetHighSchoolCertificateResponse"]["GetHighSchoolCertificateResult"]["getHighSchoolCertificateResponseDetailObject"]["CertificationDetails"] = certification_details
        response["GetHighSchoolCertificateResponse"]["GetHighSchoolCertificateResult"]["getHighSchoolCertificateResponseDetailObject"]["CoursesList"]["CourseDetails"] = courses_list
        
        # Return structured response with success status
        return {
            "status": "success",
            "data": response
        }
        
    except ET.ParseError as e:
        #logger.error(f"XML parsing error in Noor response: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Invalid XML response from Noor service: {str(e)}",
            "error_type": "xml_parsing_error"
        }
    
    except Exception as e:
        #logger.error(f"Error parsing Noor SOAP response: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Failed to parse Noor response: {str(e)}",
            "error_type": "parsing_error"
        }

def parse_noor_soap_response_v1(soap_response_xml,source):
    """
    Parse SOAP response from Noor service and extract structured student information.
    Returns response in GetHighSchoolCertificateResponse format.
    
    Args:
        soap_response_xml (str): Raw SOAP XML response from Noor service
    
    Returns:
        dict: Structured student information in GetHighSchoolCertificateResponse format
    """
    try:
        import xml.etree.ElementTree as ET
        
        # Parse the XML
        root = ET.fromstring(soap_response_xml)
        
        # Define namespaces used in the response
        namespaces = {
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'tempuri': 'http://tempuri.org/',
            'student': 'http://yefi.gov.sa/MOE/SchoolStudentRecord/xml/schemas/version4.0',
            'person': 'http://yefi.gov.sa/PersonProfileCommonTypes/xml/schemas/version2.0',
            'common': 'http://yefi.gov.sa/CommonTypes/xml/schemas/version2.0'
        }
        
        # Initialize the response structure
        response = {
            "data": {
                
            }
        }
        
        # Extract student basic information
        data = {}
        student_info_elem = root.find('.//student:StudentBasicInfo', namespaces)
        
        if student_info_elem is not None:
            # Student name in Arabic
            name_ar_elem = student_info_elem.find('.//person:PersonFullName', namespaces)
            if name_ar_elem is not None:
                data['NameAr'] = name_ar_elem.text or ""
                
            
            # Student name in English - find the second PersonFullName element
            name_elements = student_info_elem.findall('.//person:PersonFullName', namespaces)
            if len(name_elements) > 1:
                data['StudentNameEn'] = name_elements[1].text or ""
                
            
            # Gender
            gender_elem = student_info_elem.find('student:Gender', namespaces)
            if gender_elem is not None:
                data['Gender'] = gender_elem.text or ""
            

        
        
        # Extract certification details
        certification_details = {}
        cert_details_elem = root.find('.//student:CertificationDetails', namespaces)
        
        if cert_details_elem is not None:
            # Study type
            study_type_ar_elem = cert_details_elem.find('student:StudyTypeAr', namespaces)
            study_type_en_elem = cert_details_elem.find('student:StudyTypeEn', namespaces)
            if study_type_ar_elem is not None:
                certification_details['StudyTypeAr'] = study_type_ar_elem.text or ""
            if study_type_en_elem is not None:
                certification_details['StudyTypeEn'] = study_type_en_elem.text or ""
            
            # Educational level
            edu_level_elem = cert_details_elem.find('student:EducationalLevel', namespaces)
            if edu_level_elem is not None:
                certification_details['EducationalLevel'] = edu_level_elem.text or ""
            
            # Education type
            edu_type_ar_elem = cert_details_elem.find('student:EducationTypeAr', namespaces)
            edu_type_en_elem = cert_details_elem.find('student:EducationTypeEn', namespaces)
            if edu_type_ar_elem is not None:
                certification_details['EducationTypeAr'] = edu_type_ar_elem.text or ""
            if edu_type_en_elem is not None:
                certification_details['EducationTypeEn'] = edu_type_en_elem.text or ""
            
            # Major information
            major_code_elem = cert_details_elem.find('student:MajorCode', namespaces)
            major_type_ar_elem = cert_details_elem.find('student:MajorTypeAr', namespaces)
            major_type_en_elem = cert_details_elem.find('student:MajorTypeEn', namespaces)
            if major_code_elem is not None:
                certification_details['MajorCode'] = int(major_code_elem.text) if major_code_elem.text and major_code_elem.text.isdigit() else major_code_elem.text
            if major_type_ar_elem is not None:
                certification_details['MajorTypeAr'] = major_type_ar_elem.text or ""
            if major_type_en_elem is not None:
                certification_details['MajorTypeEn'] = major_type_en_elem.text or ""
            
            # GPA information
            gpa_elem = cert_details_elem.find('student:GPA', namespaces)
            gpa_type_ar_elem = cert_details_elem.find('student:GPATypeAr', namespaces)
            gpa_type_en_elem = cert_details_elem.find('student:GPATypeEn', namespaces)
            gpa_max_elem = cert_details_elem.find('student:GPAMAX', namespaces)
            gpa_degree_ar_elem = cert_details_elem.find('student:GPADegreeAr', namespaces)
            gpa_degree_en_elem = cert_details_elem.find('student:GPADegreeEn', namespaces)
            
            if gpa_elem is not None:
                try:
                    certification_details['GPA'] = float(gpa_elem.text) if gpa_elem.text else 0.0
                except ValueError:
                    certification_details['GPA'] = gpa_elem.text or ""
            if gpa_type_ar_elem is not None:
                certification_details['GPATypeAr'] = gpa_type_ar_elem.text or ""
            if gpa_type_en_elem is not None:
                certification_details['GPATypeEn'] = gpa_type_en_elem.text or ""
            if gpa_max_elem is not None:
                certification_details['GPAMAX'] = int(gpa_max_elem.text) if gpa_max_elem.text and gpa_max_elem.text.isdigit() else gpa_max_elem.text
            if gpa_degree_ar_elem is not None:
                certification_details['GPADegreeAr'] = gpa_degree_ar_elem.text or ""
            if gpa_degree_en_elem is not None:
                certification_details['GPADegreeEn'] = gpa_degree_en_elem.text or ""
            
            # Certification years
            cert_hijri_year_elem = cert_details_elem.find('student:CertificationHijriYear', namespaces)
            cert_greg_year_elem = cert_details_elem.find('student:CertificationGregYear', namespaces)
            if cert_hijri_year_elem is not None:
                certification_details['CertificationHijriYear'] = cert_hijri_year_elem.text or ""
            if cert_greg_year_elem is not None:
                certification_details['CertificationGregYear'] = cert_greg_year_elem.text or ""
            
            # Graduation date - find graduation date specifically (not DOB)
            grad_date_elems = cert_details_elem.findall('.//common:GregorianDate', namespaces)
            grad_hijri_elems = cert_details_elem.findall('.//common:HijriDate', namespaces)
            graduation_date = {}
            
            
        
       
        # Populate the response structure
        response["data"]["StudentBasicInfo"] = data
        response["data"]["CertificationDetails"] = certification_details
        response["status"] = "success"
        response["source"] = source
        
        # Return structured response with success status
        return {
            "status": "success",
            "data": response
        }
        
    except ET.ParseError as e:
        #logger.error(f"XML parsing error in Noor response: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Invalid XML response from Noor service: {str(e)}",
            "error_type": "xml_parsing_error"
        }
    
    except Exception as e:
        #logger.error(f"Error parsing Noor SOAP response: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Failed to parse Noor response: {str(e)}",
            "error_type": "parsing_error"
        }


def call_moahal_soap_service(endpoint_url, action, identity_number, headers=None):
    """
    SOAP client function to call Moahal service for qualifications information.
    
    Args:
        endpoint_url (str): The SOAP endpoint URL
        action (str): The SOAP action/method to call
        identity_number (str): Identity Number to lookup qualifications in Moahal system
        headers (dict): Additional headers to include in the request
    
    Returns:
        dict: Response from the SOAP service
    """
    try:
        # Default SOAP headers matching Moahal service requirements
        default_headers = {
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': action
        }
        
        # Merge with custom headers if provided
        if headers:
            default_headers.update(headers)
        
        # Build SOAP envelope based on Moahal service requirements
        soap_envelope = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
                <soapenv:Header/>
                <soapenv:Body>
                    <tem:GetQualifications>
                        <tem:IdentityNumber>{identity_number}</tem:IdentityNumber>
                    </tem:GetQualifications>
                </soapenv:Body>
                </soapenv:Envelope>"""
        
        # Log the request for debugging
        ##logger.info(f"Calling Moahal SOAP service: {endpoint_url}")
        ##logger.info(f"Action: {action}")
        ##logger.info(f"IdentityNumber: {identity_number}")
        
        # Make the SOAP request
        response = requests.post(
            endpoint_url,
            data=soap_envelope,
            headers=default_headers,
            timeout=30  # 30-second timeout
        )
        
        # Check for HTTP errors
        response.raise_for_status()
        
        # Parse the SOAP response
        response_data = {
            "status": "success",
            "soap_response": response.text,
            "status_code": response.status_code,
            "headers": dict(response.headers)
        }
        
        ##logger.info(f"Moahal SOAP service response received successfully")
        return response_data
        
    except requests.exceptions.Timeout:
        error_msg = "Moahal SOAP service request timed out"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "timeout"
        }
        
    except requests.exceptions.ConnectionError:
        error_msg = "Failed to connect to Moahal SOAP service"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "connection_error"
        }
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP error from Moahal SOAP service: {e.response.status_code}"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "http_error",
            "status_code": e.response.status_code
        }
        
    except Exception as e:
        error_msg = f"Unexpected error calling Moahal SOAP service: {str(e)}"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "unexpected_error"
        }


def parse_moahal_soap_response(soap_response_xml):
    """
    Parse SOAP response from Moahal service and extract structured qualifications information.
    
    Args:
        soap_response_xml (str): Raw SOAP XML response from Moahal service
    
    Returns:
        dict: Structured qualifications information in GetQualificationsResponse format
    """
    try:
        import xml.etree.ElementTree as ET
        
        # Parse the XML
        root = ET.fromstring(soap_response_xml)
        
        # Define namespaces based on actual Moahal response structure
        namespaces = {
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'tempuri': 'http://tempuri.org/',
            'qual': 'http://yefi.gov.sa/MOE/QualificationsServiceSchema/xml/schemas/version3.0',
            'common': 'http://yefi.gov.sa/CommonTypes/xml/schemas/version2.0'
        }
        
        # Initialize response structure
        person_details = {
            "NationalityName": "",
            "EmailAddress": "",
            "PersonName": {
                "FullNameAr": "",
                "FullNameEn": ""
            }
        }
        
        abroad_qualification_response = {
            "ResponseStatus": 3
        }
        
        local_high_qualifications_response = {
            "ResponseStatus": 1,
            "LocalHighQualificationsList": {
                "LocalHighQualifications": []
            }
        }
        
        # Extract person details
        person_elem = root.find('.//qual:PersonDetails', namespaces)
        
        if person_elem is not None:
            # Nationality
            nationality_elem = person_elem.find('qual:NationalityName', namespaces)
            if nationality_elem is not None and nationality_elem.text:
                person_details['NationalityName'] = nationality_elem.text
            
            # Email
            email_elem = person_elem.find('qual:EmailAddress', namespaces)
            if email_elem is not None and email_elem.text:
                person_details['EmailAddress'] = email_elem.text
            
            # Person name
            person_name_elem = person_elem.find('qual:PersonName', namespaces)
            if person_name_elem is not None:
                full_name_ar_elem = person_name_elem.find('qual:FullNameAr', namespaces)
                full_name_en_elem = person_name_elem.find('qual:FullNameEn', namespaces)
                
                if full_name_ar_elem is not None and full_name_ar_elem.text:
                    person_details['PersonName']['FullNameAr'] = full_name_ar_elem.text
                if full_name_en_elem is not None and full_name_en_elem.text:
                    person_details['PersonName']['FullNameEn'] = full_name_en_elem.text
        
        # Extract abroad qualifications response status
        abroad_elem = root.find('.//qual:AbroadQualiffcationResponse', namespaces)
        if abroad_elem is not None:
            response_status_elem = abroad_elem.find('qual:ResponseStatus', namespaces)
            if response_status_elem is not None and response_status_elem.text:
                try:
                    abroad_qualification_response['ResponseStatus'] = int(response_status_elem.text)
                except ValueError:
                    abroad_qualification_response['ResponseStatus'] = 3
        
        # Extract local high qualifications
        local_response_elem = root.find('.//qual:LocalHighQualificationsResponse', namespaces)
        
        if local_response_elem is not None:
            # Response status
            response_status_elem = local_response_elem.find('qual:ResponseStatus', namespaces)
            if response_status_elem is not None and response_status_elem.text:
                try:
                    local_high_qualifications_response['ResponseStatus'] = int(response_status_elem.text)
                except ValueError:
                    local_high_qualifications_response['ResponseStatus'] = 1
            
            # Qualifications list
            qual_list_elem = local_response_elem.find('qual:LocalHighQualificationsList', namespaces)
            if qual_list_elem is not None:
                qualifications = qual_list_elem.findall('qual:LocalHighQualifications', namespaces)
                
                # Process all qualifications
                qualifications_list = []
                for qual in qualifications:
                    qualification_info = {
                        "InstituteName": "",
                        "CollegeName": "",
                        "SectionName": "",
                        "MajorName": "",
                        "MinorName": "",
                        "SaudiSpeciality": "",
                        "StudyPeriod": 0,
                        "StudyModeName": "",
                        "GPATypeName": "",
                        "GPA": 0.0,
                        "RatingName": "",
                        "SaudiMajor": {
                            "SaudiMajorCode": "",
                            "SaudiMajorAr": ""
                        },
                        "SaudiEducationLevel": {
                            "SaudiEducationLevelCode": 0,
                            "SaudiEducationLevelAr": ""
                        },
                        "GraduationDate": {
                            "GregorianDate": "",
                            "HijriDate": ""
                        },
                        "Degree": "",
                        "DegreeName": ""
                    }
                    
                    # Extract fields
                    institute_elem = qual.find('qual:InstituteName', namespaces)
                    if institute_elem is not None and institute_elem.text:
                        qualification_info['InstituteName'] = institute_elem.text
                    
                    college_elem = qual.find('qual:CollegeName', namespaces)
                    if college_elem is not None and college_elem.text:
                        qualification_info['CollegeName'] = college_elem.text
                    
                    section_elem = qual.find('qual:SectionName', namespaces)
                    if section_elem is not None and section_elem.text:
                        qualification_info['SectionName'] = section_elem.text
                    
                    major_elem = qual.find('qual:MajorName', namespaces)
                    if major_elem is not None and major_elem.text:
                        qualification_info['MajorName'] = major_elem.text
                    
                    minor_elem = qual.find('qual:MinorName', namespaces)
                    if minor_elem is not None and minor_elem.text:
                        qualification_info['MinorName'] = minor_elem.text
                    
                    saudi_speciality_elem = qual.find('qual:SaudiSpeciality', namespaces)
                    if saudi_speciality_elem is not None and saudi_speciality_elem.text:
                        qualification_info['SaudiSpeciality'] = saudi_speciality_elem.text
                    
                    study_period_elem = qual.find('qual:StudyPeriod', namespaces)
                    if study_period_elem is not None and study_period_elem.text:
                        try:
                            qualification_info['StudyPeriod'] = int(study_period_elem.text)
                        except ValueError:
                            qualification_info['StudyPeriod'] = 0
                    
                    study_mode_elem = qual.find('qual:StudyModeName', namespaces)
                    if study_mode_elem is not None and study_mode_elem.text:
                        qualification_info['StudyModeName'] = study_mode_elem.text
                    
                    gpa_type_elem = qual.find('qual:GPATypeName', namespaces)
                    if gpa_type_elem is not None and gpa_type_elem.text:
                        qualification_info['GPATypeName'] = gpa_type_elem.text
                    
                    gpa_elem = qual.find('qual:GPA', namespaces)
                    if gpa_elem is not None and gpa_elem.text:
                        try:
                            qualification_info['GPA'] = float(gpa_elem.text)
                        except ValueError:
                            qualification_info['GPA'] = 0.0
                    
                    rating_elem = qual.find('qual:RatingName', namespaces)
                    if rating_elem is not None and rating_elem.text:
                        qualification_info['RatingName'] = rating_elem.text
                    
                    # Saudi major information
                    saudi_major_elem = qual.find('qual:SaudiMajor', namespaces)
                    if saudi_major_elem is not None:
                        saudi_major_code_elem = saudi_major_elem.find('qual:SaudiMajorCode', namespaces)
                        saudi_major_ar_elem = saudi_major_elem.find('qual:SaudiMajorAr', namespaces)
                        
                        if saudi_major_code_elem is not None and saudi_major_code_elem.text:
                            qualification_info['SaudiMajor']['SaudiMajorCode'] = saudi_major_code_elem.text
                        if saudi_major_ar_elem is not None and saudi_major_ar_elem.text:
                            qualification_info['SaudiMajor']['SaudiMajorAr'] = saudi_major_ar_elem.text
                    
                    # Saudi education level
                    saudi_edu_level_elem = qual.find('qual:SaudiEducationLevel', namespaces)
                    if saudi_edu_level_elem is not None:
                        level_code_elem = saudi_edu_level_elem.find('qual:SaudiEducationLevelCode', namespaces)
                        level_ar_elem = saudi_edu_level_elem.find('qual:SaudiEducationLevelAr', namespaces)
                        
                        if level_code_elem is not None and level_code_elem.text:
                            try:
                                qualification_info['SaudiEducationLevel']['SaudiEducationLevelCode'] = int(level_code_elem.text)
                            except ValueError:
                                qualification_info['SaudiEducationLevel']['SaudiEducationLevelCode'] = 0
                        if level_ar_elem is not None and level_ar_elem.text:
                            qualification_info['SaudiEducationLevel']['SaudiEducationLevelAr'] = level_ar_elem.text
                    
                    # Graduation date
                    graduation_elem = qual.find('qual:GraduationDate', namespaces)
                    if graduation_elem is not None:
                        greg_date_elem = graduation_elem.find('common:GregorianDate', namespaces)
                        hijri_date_elem = graduation_elem.find('common:HijriDate', namespaces)
                        
                        if greg_date_elem is not None and greg_date_elem.text:
                            qualification_info['GraduationDate']['GregorianDate'] = greg_date_elem.text
                        if hijri_date_elem is not None and hijri_date_elem.text:
                            qualification_info['GraduationDate']['HijriDate'] = hijri_date_elem.text
                    
                    # Degree information
                    degree_elem = qual.find('qual:Degree', namespaces)
                    if degree_elem is not None and degree_elem.text:
                        qualification_info['Degree'] = degree_elem.text
                    
                    degree_name_elem = qual.find('qual:DegreeName', namespaces)
                    if degree_name_elem is not None and degree_name_elem.text:
                        qualification_info['DegreeName'] = degree_name_elem.text
                    
                    # Add this qualification to the list
                    qualifications_list.append(qualification_info)
                
                # Set the complete list of qualifications
                local_high_qualifications_response['LocalHighQualificationsList']['LocalHighQualifications'] = qualifications_list
        
        # Return the exact format requested
        return {
            "GetQualificationsResponse": {
                "GetQualificationsResult": {
                    "getQualificationsResponseDetailObject": {
                        "QualificationsDetailsResponse": {
                            "PersonDetails": person_details
                        },
                        "AbroadQualiffcationResponse": abroad_qualification_response,
                        "LocalHighQualificationsResponse": local_high_qualifications_response
                    }
                }
            }
        }
        
    except ET.ParseError as e:
        #logger.error(f"XML parsing error in Moahal response: {str(e)}")
        return {
            "GetQualificationsResponse": {
                "GetQualificationsResult": {
                    "getQualificationsResponseDetailObject": {
                        "error": f"Invalid XML response from Moahal service: {str(e)}",
                        "error_type": "xml_parsing_error"
                    }
                }
            }
        }
    
    except Exception as e:
        #logger.error(f"Error parsing Moahal SOAP response: {str(e)}")
        return {
            "GetQualificationsResponse": {
                "GetQualificationsResult": {
                    "getQualificationsResponseDetailObject": {
                        "error": f"Failed to parse Moahal response: {str(e)}",
                        "error_type": "parsing_error"
                    }
                }
            }
        }


def call_disability_soap_service(endpoint_url, action, identifier, identifier_type, headers=None):
    """
    SOAP client function to call Disability service for disability information.
    
    Args:
        endpoint_url (str): The SOAP endpoint URL
        action (str): The SOAP action/method to call
        identifier (str): Person identifier (National ID)
        identifier_type (str): Type of identifier (NationalIdentity)
        headers (dict): Additional headers to include in the request
    
    Returns:
        dict: Response from the SOAP service
    """
    try:
        # Default SOAP headers
        default_headers = {
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': action
        }
        
        # Merge with custom headers if provided
        if headers:
            default_headers.update(headers)
        
        # Build SOAP envelope based on Disability service requirements
        soap_envelope = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
                <soapenv:Header/>
                <soapenv:Body>
                    <tem:GetDisabilityInfo>
                        <tem:Identifier>{identifier}</tem:Identifier>
                        <tem:IdentifierType>{identifier_type}</tem:IdentifierType>
                    </tem:GetDisabilityInfo>
                </soapenv:Body>
                </soapenv:Envelope>"""
        
        # Log the request for debugging
        ##logger.info(f"Calling Disability SOAP service: {endpoint_url}")
        ##logger.info(f"Action: {action}")
        ##logger.info(f"Identifier: {identifier}, Type: {identifier_type}")
        
        # Make the SOAP request
        response = requests.post(
            endpoint_url,
            data=soap_envelope,
            headers=default_headers,
            timeout=30
        )
        
        # Check for HTTP errors
        response.raise_for_status()
        
        # Parse the SOAP response
        response_data = {
            "status": "success",
            "soap_response": response.text,
            "status_code": response.status_code,
            "headers": dict(response.headers)
        }
        
        ##logger.info(f"Disability SOAP service response received successfully")
        return response_data
        
    except requests.exceptions.Timeout:
        error_msg = "Disability SOAP service request timed out"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "timeout"
        }
        
    except requests.exceptions.ConnectionError:
        error_msg = "Failed to connect to Disability SOAP service"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "connection_error"
        }
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP error from Disability SOAP service: {e.response.status_code}"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "http_error",
            "status_code": e.response.status_code
        }
        
    except Exception as e:
        error_msg = f"Unexpected error calling Disability SOAP service: {str(e)}"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "unexpected_error"
        }


def parse_disability_soap_response(soap_response_xml):
    """
    Parse SOAP response from Disability service and extract structured disability information.
    """
    try:
        import xml.etree.ElementTree as ET
        
        # Parse the XML
        root = ET.fromstring(soap_response_xml)
        
        # Define namespaces
        namespaces = {
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'tempuri': 'http://tempuri.org/',
            'disability': 'http://yefi.gov.sa/MOSA/DisabilityReportSchema/xml/schemas/version1.0',
            'person': 'http://yefi.gov.sa/PersonProfileCommonTypes/xml/schemas/version2.0',
            'yefi': 'http://yefi.gov.sa/YEFIErrorStructure/xml/schemas/version2.3'
        }
        
        # Check for service errors first
        error_element = root.find('.//yefi:ServiceError', namespaces)
        if error_element is not None:
            error_code = error_element.find('yefi:Code', namespaces)
            error_text = error_element.find('yefi:ErrorText', namespaces)
            
            return {
                "status": "error",
                "error_message": error_text.text.strip() if error_text is not None else "Unknown error",
                "error_code": error_code.text.strip() if error_code is not None else "Unknown",
                "error_type": "service_error",
                "raw_response": soap_response_xml
            }
        
        # Parse successful response
        disability_info = {}
        
        # Extract person name
        person_name = {}
        first_name = root.find('.//person:FirstName', namespaces)
        second_name = root.find('.//person:SecondName', namespaces)
        third_name = root.find('.//person:ThirdName', namespaces)
        last_name = root.find('.//person:LastName', namespaces)
        
        if first_name is not None:
            person_name['first_name'] = first_name.text.strip()
        if second_name is not None:
            person_name['second_name'] = second_name.text.strip()
        if third_name is not None:
            person_name['third_name'] = third_name.text.strip()
        if last_name is not None:
            person_name['last_name'] = last_name.text.strip()
        
        # Create full name
        name_parts = [person_name.get('first_name', ''), person_name.get('second_name', ''), 
                     person_name.get('third_name', ''), person_name.get('last_name', '')]
        full_name = ' '.join(filter(None, name_parts))
        
        if full_name:
            disability_info['person_name'] = person_name
            disability_info['full_name'] = full_name
        
        # Extract age
        age_element = root.find('.//disability:Age', namespaces)
        if age_element is not None:
            disability_info['age'] = age_element.text.strip()
        
        # Extract gender
        gender_element = root.find('.//disability:Gender', namespaces)
        if gender_element is not None:
            disability_info['gender'] = gender_element.text.strip()
        
        # Extract disabilities
        disabilities = []
        disability_elements = root.findall('.//disability:Disability', namespaces)
        
        for disability_elem in disability_elements:
            disability_data = {}
            
            # Disability type
            disability_type = disability_elem.find('disability:DisabilityType', namespaces)
            if disability_type is not None:
                disability_data['disability_type'] = disability_type.text.strip()
            
            # Disability date
            disability_date = disability_elem.find('disability:DisabilityDate', namespaces)
            if disability_date is not None:
                disability_data['disability_date'] = disability_date.text.strip()
            
            if disability_data:
                disabilities.append(disability_data)
        
        if disabilities:
            disability_info['disabilities'] = disabilities
            disability_info['total_disabilities'] = len(disabilities)
        
        return {
            "status": "success",
            "disability_info": disability_info,
           
        }
        
    except ET.ParseError as e:
        #logger.error(f"XML parsing error in Disability response: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Invalid XML response from Disability service: {str(e)}",
            "error_type": "xml_parsing_error"
        }
    
    except Exception as e:
        #logger.error(f"Error parsing Disability SOAP response: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Failed to parse Disability response: {str(e)}",
            "error_type": "parsing_error"
        }


def parse_disability_soap_response_v1(soap_response_xml):
    """
    Parse SOAP response from Disability service and extract structured disability information.
    """
    try:
        import xml.etree.ElementTree as ET
        
        # Parse the XML
        root = ET.fromstring(soap_response_xml)
        
        # Define namespaces
        namespaces = {
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'tempuri': 'http://tempuri.org/',
            'disability': 'http://yefi.gov.sa/MOSA/DisabilityReportSchema/xml/schemas/version1.0',
            'person': 'http://yefi.gov.sa/PersonProfileCommonTypes/xml/schemas/version2.0',
            'yefi': 'http://yefi.gov.sa/YEFIErrorStructure/xml/schemas/version2.3'
        }
        
        # Check for service errors first
        error_element = root.find('.//yefi:ServiceError', namespaces)
        if error_element is not None:
            error_code = error_element.find('yefi:Code', namespaces)
            error_text = error_element.find('yefi:ErrorText', namespaces)
            
            return {
                "status": "error",
                "error_message": error_text.text.strip() if error_text is not None else "Unknown error",
                "error_code": error_code.text.strip() if error_code is not None else "Unknown",
                "error_type": "service_error",
                "raw_response": soap_response_xml
            }
        
        # Parse successful response
        disability_info = {}
        
        # Extract person name
        person_name = {}
        first_name = root.find('.//person:FirstName', namespaces)
        second_name = root.find('.//person:SecondName', namespaces)
        third_name = root.find('.//person:ThirdName', namespaces)
        last_name = root.find('.//person:LastName', namespaces)
        
        if first_name is not None:
            person_name['first_name'] = first_name.text.strip()
        if second_name is not None:
            person_name['second_name'] = second_name.text.strip()
        if third_name is not None:
            person_name['third_name'] = third_name.text.strip()
        if last_name is not None:
            person_name['last_name'] = last_name.text.strip()
        
        # Create full name
        name_parts = [person_name.get('first_name', ''), person_name.get('second_name', ''), 
                     person_name.get('third_name', ''), person_name.get('last_name', '')]
        full_name = ' '.join(filter(None, name_parts))
        
        if full_name:
            #disability_info['person_name'] = person_name
            disability_info['full_name'] = full_name
        
        # # Extract age
        # age_element = root.find('.//disability:Age', namespaces)
        # if age_element is not None:
        #     disability_info['age'] = age_element.text.strip()
        
        # # Extract gender
        # gender_element = root.find('.//disability:Gender', namespaces)
        # if gender_element is not None:
        #     disability_info['gender'] = gender_element.text.strip()
        
        # Extract disabilities
        disabilities = []
        disability_elements = root.findall('.//disability:Disability', namespaces)
        
        for disability_elem in disability_elements:
            disability_data = {}
            
            # Disability type
            disability_type = disability_elem.find('disability:DisabilityType', namespaces)
            if disability_type is not None:
                disability_data['disability_type'] = disability_type.text.strip()
            
            # Disability date
            # disability_date = disability_elem.find('disability:DisabilityDate', namespaces)
            # if disability_date is not None:
            #     disability_data['disability_date'] = disability_date.text.strip()
            
            if disability_data:
                disabilities.append(disability_data)
        
        if disabilities:
            disability_info['disabilities'] = disabilities
            disability_info['total_disabilities'] = len(disabilities)
        
        return {
            "status": "success",
            "disability_info": disability_info,
           
        }
        
    except ET.ParseError as e:
        #logger.error(f"XML parsing error in Disability response: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Invalid XML response from Disability service: {str(e)}",
            "error_type": "xml_parsing_error"
        }
    
    except Exception as e:
        #logger.error(f"Error parsing Disability SOAP response: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Failed to parse Disability response: {str(e)}",
            "error_type": "parsing_error"
        }



def call_social_security_soap_service(endpoint_url, action, national_id, headers=None):
    """
    SOAP client function to call Social Security service for indigent inquiry.
    
    Args:
        endpoint_url (str): The SOAP endpoint URL
        action (str): The SOAP action/method to call
        national_id (str): National ID to lookup social security information
        headers (dict): Additional headers to include in the request
    
    Returns:
        dict: Response from the SOAP service
    """
    try:
        # Default SOAP headers
        default_headers = {
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': action
        }
        
        # Merge with custom headers if provided
        if headers:
            default_headers.update(headers)
        
        # Build SOAP envelope based on Social Security service requirements
        soap_envelope = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
                <soapenv:Header/>
                <soapenv:Body>
                    <tem:GetIndigentdByNationalId>
                        <tem:NationalID>{national_id}</tem:NationalID>
                    </tem:GetIndigentdByNationalId>
                </soapenv:Body>
                </soapenv:Envelope>"""
        
        # Log the request for debugging
        ##logger.info(f"Calling Social Security SOAP service: {endpoint_url}")
        ##logger.info(f"Action: {action}")
        ##logger.info(f"NationalID: {national_id}")
        
        # Make the SOAP request
        response = requests.post(
            endpoint_url,
            data=soap_envelope,
            headers=default_headers,
            timeout=30
        )
        
        # Check for HTTP errors
        response.raise_for_status()
        
        # Parse the SOAP response
        response_data = {
            "status": "success",
            "soap_response": response.text,
            "status_code": response.status_code,
            "headers": dict(response.headers)
        }
        
        ##logger.info(f"Social Security SOAP service response received successfully")
        return response_data
        
    except requests.exceptions.Timeout:
        error_msg = "Social Security SOAP service request timed out"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "timeout"
        }
        
    except requests.exceptions.ConnectionError:
        error_msg = "Failed to connect to Social Security SOAP service"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "connection_error"
        }
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP error from Social Security SOAP service: {e.response.status_code}"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "http_error",
            "status_code": e.response.status_code
        }
        
    except Exception as e:
        error_msg = f"Unexpected error calling Social Security SOAP service: {str(e)}"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "unexpected_error"
        }


def parse_social_security_soap_response(soap_response_xml):
    """
    Parse SOAP response from Social Security service and extract structured indigent information.
    """
    try:
        import xml.etree.ElementTree as ET
        
        # Parse the XML
        root = ET.fromstring(soap_response_xml)
        
        # Define namespaces
        namespaces = {
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'tempuri': 'http://tempuri.org/',
            'indigent': 'http://yefi.gov.sa/MOSA/IndigentInquirySchema/xml/schemas/version1.0',
            'yefi': 'http://yefi.gov.sa/YEFIErrorStructure/xml/schemas/version2.3'
        }
        
        # Check for service errors first
        error_element = root.find('.//yefi:ServiceError', namespaces)
        if error_element is not None:
            error_code = error_element.find('yefi:Code', namespaces)
            error_text = error_element.find('yefi:ErrorText', namespaces)
            source_agency = error_element.find('yefi:SourceAgency', namespaces)
            
            return {
                "status": "error",
                "error_message": error_text.text.strip() if error_text is not None else "Unknown error",
                "error_code": error_code.text.strip() if error_code is not None else "Unknown",
                "source_agency": source_agency.text.strip() if source_agency is not None else "Unknown",
                "error_type": "service_error",
                "raw_response": soap_response_xml
            }
        
        # Parse successful response
        indigent_info = {}
        
        # Extract citizen name
        citizen_name_element = root.find('.//indigent:CitizenName', namespaces)
        if citizen_name_element is not None:
            citizen_name = citizen_name_element.text.strip()
            indigent_info['citizen_name'] = citizen_name
            
            # Split Arabic name into parts (assuming space-separated)
            name_parts = citizen_name.split()
            if len(name_parts) >= 1:
                indigent_info['name_parts'] = {
                    'first_name': name_parts[0] if len(name_parts) > 0 else '',
                    'second_name': name_parts[1] if len(name_parts) > 1 else '',
                    'third_name': name_parts[2] if len(name_parts) > 2 else '',
                    'last_name': name_parts[3] if len(name_parts) > 3 else '',
                    'remaining_names': ' '.join(name_parts[4:]) if len(name_parts) > 4 else ''
                }
        
        # Extract social security amount
        social_security_amount_element = root.find('.//indigent:SocialSecurityAmount', namespaces)
        if social_security_amount_element is not None:
            amount_text = social_security_amount_element.text.strip()
            indigent_info['social_security_amount'] = amount_text
            
            # Try to convert to numeric for easier processing
            try:
                indigent_info['social_security_amount_numeric'] = float(amount_text)
            except (ValueError, TypeError):
                # Keep as string if conversion fails
                pass
        
        # Add summary information
        if indigent_info:
            indigent_info['has_social_security'] = True
            indigent_info['record_found'] = True
        else:
            indigent_info['has_social_security'] = False
            indigent_info['record_found'] = False
        
        return {
            "status": "success",
            "indigent_info": indigent_info,
            "raw_response": soap_response_xml
        }
        
    except ET.ParseError as e:
        #logger.error(f"XML parsing error in Social Security response: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Invalid XML response from Social Security service: {str(e)}",
            "error_type": "xml_parsing_error"
        }
    
    except Exception as e:
        #logger.error(f"Error parsing Social Security SOAP response: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Failed to parse Social Security response: {str(e)}",
            "error_type": "parsing_error"
        }


def call_qiyas_soap_service(endpoint_url, action, identifier_type, identifier_value, exam_code, exam_specialty_code=None, inquiry_date=None, headers=None):
    """
    SOAP client function to call Qiyas service for exam results.
    
    Args:
        endpoint_url (str): The SOAP endpoint URL
        action (str): The SOAP action/method to call
        identifier_type (str): 'national_id' or 'iqama_number'
        identifier_value (str): The actual identifier value
        exam_code (str): Exam code ('01' for Qiyas, '04' for STEP)
        exam_specialty_code (str): Exam specialty code (optional)
        inquiry_date (str): Inquiry date (optional, format: YYYY-MM-DD)
        headers (dict): Additional headers to include in the request
    
    Returns:
        dict: Response from the SOAP service
    """
    try:
        # Default SOAP headers
        default_headers = {
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': action
        }
        
        # Merge with custom headers if provided
        if headers:
            default_headers.update(headers)
        
        # Build identifier section based on type

        identifier_xml = f"<ver:NationalID>{identifier_value}</ver:NationalID>"

        
        # Build optional fields
        if exam_specialty_code != None:
            exam_specialty_xml = f"<ExamSpecialtyCode>{exam_specialty_code}</ExamSpecialtyCode>" 
        else:
            exam_specialty_xml = f"<ExamSpecialtyCode>01</ExamSpecialtyCode>" 
       
        if inquiry_date != None:
            inquiry_date_xml = f"<InquiryDate>{inquiry_date}</InquiryDate>" if inquiry_date else ""
        else:
            inquiry_date_xml = ""
        
        # Build SOAP envelope based on Qiyas service requirements
        soap_envelope = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/" xmlns:ver="http://yefi.gov.sa/Qiyas/QiyasExamResultsSchema/xml/schemas/version4.0">
                <soapenv:Header/>
                <soapenv:Body>
                    <tem:GetExamResult>
                        <tem:request>
                            <ApplicantIdentifier>
                            {identifier_xml}
                            </ApplicantIdentifier>
                            <ExamCode>{exam_code}</ExamCode>
                            {exam_specialty_xml}
                            {inquiry_date_xml}
                        </tem:request>
                    </tem:GetExamResult>
                </soapenv:Body>
                </soapenv:Envelope>"""
        
       
        
        
        
        # # Log the request for debugging
        # ##logger.info(f"Calling Qiyas SOAP service: {endpoint_url}")
        # ##logger.info(f"Action: {action}")
        # ##logger.info(f"Identifier Type: {identifier_type}, Value: {identifier_value}")
        # ##logger.info(f"Exam Code: {exam_code}")
        
        # Make the SOAP request
        response = requests.post(
            endpoint_url,
            data=soap_envelope,
            headers=default_headers,
            timeout=30
        )
        
        # Check for HTTP errors
        response.raise_for_status()
        #print('response',response.text)
        # Parse the SOAP response
        response_data = {
            "status": "success",
            "soap_response": response.text,
            "status_code": response.status_code,
            "headers": dict(response.headers)
        }
        
        ##logger.info(f"Qiyas SOAP service response received successfully")
        return response_data
        
    except requests.exceptions.Timeout:
        error_msg = "Qiyas SOAP service request timed out"
        ##logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "timeout"
        }
        
    except requests.exceptions.ConnectionError:
        error_msg = "Failed to connect to Qiyas SOAP service"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "connection_error"
        }
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP error from Qiyas SOAP service: {e.response.status_code}"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "http_error",
            "status_code": e.response.status_code
        }
        
    except Exception as e:
        error_msg = f"Unexpected error calling Qiyas SOAP service: {str(e)}"
        #logger.error(error_msg)
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "unexpected_error"
        }


def parse_qiyas_soap_response(soap_response_xml):
    """
    Parse SOAP response from Qiyas service and extract structured exam results.
    """
    try:
        import xml.etree.ElementTree as ET
        
        # Parse the XML
        root = ET.fromstring(soap_response_xml)
        
        # Define namespaces
        namespaces = {
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'tempuri': 'http://tempuri.org/',
            'qiyas': 'http://yefi.gov.sa/Qiyas/QiyasExamResultsSchema/xml/schemas/version4.0',
            'yefi': 'http://yefi.gov.sa/YEFIErrorStructure/xml/schemas/version2.3'
        }
        
        # Check for service errors first
        error_element = root.find('.//yefi:ServiceError', namespaces)
        if error_element is not None:
            error_code = error_element.find('yefi:Code', namespaces)
            error_text = error_element.find('yefi:ErrorText', namespaces)
            source_agency = error_element.find('yefi:SourceAgency', namespaces)
            
            return {
                "status": "error",
                "error_message": error_text.text.strip() if error_text is not None else "Unknown error",
                "error_code": error_code.text.strip() if error_code is not None else "Unknown",
                "source_agency": source_agency.text.strip() if source_agency is not None else "Unknown",
                "error_type": "service_error",
                "raw_response": soap_response_xml
            }
        
        # Parse successful response
        exam_results = {}
        
        # Extract exam type
        exam_type_element = root.find('.//qiyas:ExamType', namespaces)
        if exam_type_element is not None:
            exam_results['exam_type'] = exam_type_element.text.strip()
        
        # Extract exam specialty
        exam_specialty_element = root.find('.//qiyas:ExamSpecialty', namespaces)
        if exam_specialty_element is not None:
            exam_results['exam_specialty'] = exam_specialty_element.text.strip()
        
        # Extract exam date
        exam_date_element = root.find('.//qiyas:ExamDate', namespaces)
        if exam_date_element is not None:
            exam_results['exam_date'] = exam_date_element.text.strip()
        
        # Extract exam result details
        exam_result_container = root.find('.//qiyas:ExamResult', namespaces)
        if exam_result_container is not None:
            # Extract the actual score
            exam_result_element = exam_result_container.find('qiyas:ExamResult', namespaces)
            if exam_result_element is not None:
                score_text = exam_result_element.text.strip()
                exam_results['exam_score'] = score_text
                
                # Try to convert to numeric for easier processing
                try:
                    exam_results['exam_score_numeric'] = float(score_text)
                except (ValueError, TypeError):
                    # Keep as string if conversion fails
                    pass
            
            # Extract result type in Arabic
            result_type_ar_element = exam_result_container.find('qiyas:ExamResultTypeAr', namespaces)
            if result_type_ar_element is not None:
                exam_results['result_type_arabic'] = result_type_ar_element.text.strip()
            
            # Extract result type in English
            result_type_en_element = exam_result_container.find('qiyas:ExamResultTypeEn', namespaces)
            if result_type_en_element is not None:
                exam_results['result_type_english'] = result_type_en_element.text.strip()
            
            # Extract maximum possible score
            max_result_element = exam_result_container.find('qiyas:MaxExamResult', namespaces)
            if max_result_element is not None:
                max_score_text = max_result_element.text.strip()
                exam_results['max_score'] = max_score_text
                
                # Try to convert to numeric
                try:
                    exam_results['max_score_numeric'] = float(max_score_text)
                except (ValueError, TypeError):
                    pass
            
            # Extract applicant name
            applicant_name_element = exam_result_container.find('qiyas:ApplicantName', namespaces)
            if applicant_name_element is not None:
                applicant_name = {}
                
                first_name = applicant_name_element.find('qiyas:FirstName', namespaces)
                if first_name is not None:
                    applicant_name['first_name'] = first_name.text.strip()
                
                second_name = applicant_name_element.find('qiyas:SecondName', namespaces)
                if second_name is not None:
                    applicant_name['second_name'] = second_name.text.strip()
                
                third_name = applicant_name_element.find('qiyas:ThirdName', namespaces)
                if third_name is not None:
                    applicant_name['third_name'] = third_name.text.strip()
                
                last_name = applicant_name_element.find('qiyas:LastName', namespaces)
                if last_name is not None:
                    applicant_name['last_name'] = last_name.text.strip()
                
                # Create full name
                name_parts = [applicant_name.get('first_name', ''), applicant_name.get('second_name', ''), 
                             applicant_name.get('third_name', ''), applicant_name.get('last_name', '')]
                full_name = ' '.join(filter(None, name_parts))
                
                if applicant_name:
                    exam_results['applicant_name'] = applicant_name
                    exam_results['applicant_full_name'] = full_name
        
        # Add summary information
        if exam_results:
            exam_results['has_exam_results'] = True
            exam_results['record_found'] = True
            
            # Calculate percentage if we have both score and max score
            if 'exam_score_numeric' in exam_results and 'max_score_numeric' in exam_results:
                if exam_results['max_score_numeric'] > 0:
                    percentage = (exam_results['exam_score_numeric'] / exam_results['max_score_numeric']) * 100
                    exam_results['score_percentage'] = round(percentage, 2)
        else:
            exam_results['has_exam_results'] = False
            exam_results['record_found'] = False
        
        #print('exam_results',exam_results)
        return {
            "status": "success",
            "exam_results": exam_results,
            "raw_response": soap_response_xml
        }
        
    except ET.ParseError as e:
        #logger.error(f"XML parsing error in Qiyas response: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Invalid XML response from Qiyas service: {str(e)}",
            "error_type": "xml_parsing_error"
        }
    
    except Exception as e:
        #logger.error(f"Error parsing Qiyas SOAP response: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Failed to parse Qiyas response: {str(e)}",
            "error_type": "parsing_error"
        }


def call_national_address_soap_service(endpoint_url: str, action: str, identifier: str, headers: dict = None) -> Dict[str, str]:
    """
    Call National Address SOAP service to get individual Wasel address information.
    
    Args:
        endpoint_url: SOAP service endpoint URL
        action: SOAP action
        identifier: National ID or Iqama number
        headers: Custom headers for the request
    
    Returns:
        Dict containing status and response data
    """
    try:
        # Build SOAP envelope
        soap_envelope = f"""<?xml version="1.0" encoding="utf-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
        <soapenv:Header/>
        <soapenv:Body>
            <tem:GetIndividualWaselAddress>
                <tem:Identifier>{identifier}</tem:Identifier>
            </tem:GetIndividualWaselAddress>
        </soapenv:Body>
        </soapenv:Envelope>"""
        
        # Default headers
        default_headers = {
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': action,
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent': 'python-requests/2.25.1',
            'Accept': '*/*'
        }
        
        # Merge with custom headers if provided
        if headers:
            default_headers.update(headers)
        
        ##logger.info(f"Calling National Address SOAP service for identifier: {identifier}")
        
        # Make the SOAP request
        response = requests.post(
            endpoint_url,
            data=soap_envelope,
            headers=default_headers,
            timeout=30
        )
        
        ##logger.info(f"National Address SOAP response status: {response.status_code}")
        
        if response.status_code == 200:
            return {
                "status": "success",
                "soap_response": response.text,
                "status_code": response.status_code
            }
        else:
            return {
                "status": "error",
                "error_message": f"SOAP service returned status {response.status_code}",
                "error_type": "http_error",
                "status_code": response.status_code,
                "soap_response": response.text
            }
            
    except requests.exceptions.Timeout:
        #logger.error("National Address SOAP service timeout")
        return {
            "status": "error",
            "error_message": "Request timeout - SOAP service did not respond within 30 seconds",
            "error_type": "timeout_error"
        }
    
    except requests.exceptions.ConnectionError:
        #logger.error("National Address SOAP service connection error")
        return {
            "status": "error",
            "error_message": "Could not connect to National Address SOAP service",
            "error_type": "connection_error"
        }
    
    except Exception as e:
        #logger.error(f"Error calling National Address SOAP service: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Failed to call National Address service: {str(e)}",
            "error_type": "service_error"
        }


def parse_national_address_soap_response(soap_response_xml: str) -> Dict[str, any]:
    """
    Parse National Address SOAP response XML and extract address information.
    
    Args:
        soap_response_xml: Raw SOAP response XML string
    
    Returns:
        Dict containing parsed address data with status information
    """
    try:
        import xml.etree.ElementTree as ET
        
        ##logger.info("Parsing National Address SOAP response")
        #logger.debug(f"SOAP Response XML: {soap_response_xml}")
        
        # Parse XML
        root = ET.fromstring(soap_response_xml)
        
        # Define namespaces
        namespaces = {
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'ns': 'http://tempuri.org/',
            'wasel': 'http://yefi.gov.sa/SaudiPost/WaselAddressSchema/xml/schemas/version1.0'
        }
        
        # Initialize address info with default values
        address_info = {
            'record_found': False,
            'has_address': False,
            'status': 'error',
            'message': 'No address data found'
        }
        
        # Check for SOAP fault first
        fault_elem = root.find('.//s:Fault', namespaces)
        if fault_elem is not None:
            fault_string = fault_elem.find('.//faultstring')
            fault_detail = fault_elem.find('.//detail')
            error_message = fault_string.text if fault_string is not None else "SOAP Fault occurred"
            
            if fault_detail is not None:
                error_message += f" - Detail: {fault_detail.text}"
            
            return {
                "status": "error",
                "error_message": error_message,
                "error_type": "soap_fault",
                "address_info": address_info
            }
        
        # Look for the response element with multiple search patterns
        response_elem = None
        
        # Try with namespace first
        response_elem = root.find('.//ns:GetIndividualWaselAddressResponse', namespaces)
        
        # Try without namespace
        if response_elem is None:
            response_elem = root.find('.//GetIndividualWaselAddressResponse')
        
        # Try direct path through Body
        if response_elem is None:
            body_elem = root.find('.//s:Body', namespaces)
            if body_elem is not None:
                response_elem = body_elem.find('GetIndividualWaselAddressResponse')
        
        #logger.debug(f"Found response element: {response_elem is not None}")
        
        if response_elem is not None:
            # The response element has namespace, so we need to use it for child elements
            # Look for the result element with both approaches
            result_elem = None
            
            # First try: direct child with namespace consideration
            for child in response_elem:
                if child.tag.endswith('GetIndividualWaselAddressResult'):
                    result_elem = child
                    break
            
            # Second try: xpath search
            if result_elem is None:
                result_elem = response_elem.find('.//GetIndividualWaselAddressResult')
            
            #logger.debug(f"Found result element: {result_elem is not None}")
            #if result_elem is not None:
                #logger.debug(f"Result element tag: {result_elem.tag}")
            
            if result_elem is not None:
                # Look for the detail object
                detail_elem = None
                
                # First try: direct child
                for child in result_elem:
                    if child.tag.endswith('getIndividualWaselAddressResponseDetailObject'):
                        detail_elem = child
                        break
                
                # Second try: xpath search
                if detail_elem is None:
                    detail_elem = result_elem.find('.//getIndividualWaselAddressResponseDetailObject')
                
                #logger.debug(f"Found detail element: {detail_elem is not None}")
                #if detail_elem is not None:
                    #logger.debug(f"Detail element tag: {detail_elem.tag}")
                
                if detail_elem is not None:
                    # Look for WaselAddress element - try multiple approaches
                    wasel_elem = None
                    
                    # First try: direct child
                    for child in detail_elem:
                        if child.tag.endswith('WaselAddress'):
                            wasel_elem = child
                            break
                    
                    # Second try: xpath searches
                    if wasel_elem is None:
                        wasel_elem = detail_elem.find('WaselAddress')
                    if wasel_elem is None:
                        wasel_elem = detail_elem.find('.//WaselAddress')
                    if wasel_elem is None:
                        wasel_elem = detail_elem.find('wasel:WaselAddress', namespaces)
                    
                    #logger.debug(f"Found WaselAddress element: {wasel_elem is not None}")
                    #if wasel_elem is not None:
                        #logger.debug(f"WaselAddress element tag: {wasel_elem.tag}")
                    
                    if wasel_elem is not None:
                        address_info['record_found'] = True
                        address_info['has_address'] = True
                        address_info['status'] = 'success'
                        address_info['message'] = 'Address information retrieved successfully'
                        
                        # Extract address fields
                        address_fields = {
                            'building_number': 'BuildingNumber',
                            'additional_number': 'AdditionalNumber',
                            'zip_code': 'ZipCode',
                            'unit_number': 'UnitNumber',
                            'district_area_arabic': 'DistrictAreaArabic',
                            'district_area_english': 'DistrictAreaEnglish',
                            'street_name_arabic': 'StreetNameArabic',
                            'street_name_english': 'StreetNameEnglish',
                            'city_name_arabic': 'CityNameArabic',
                            'city_name_english': 'CityNameEnglish',
                            'full_name': 'FullName'
                        }
                        
                        #logger.debug("Extracting address fields...")
                        #logger.debug(f"WaselAddress children count: {len(list(wasel_elem))}")
                        
                        for key, xml_field in address_fields.items():
                            # Try multiple approaches to find the field
                            elem = None
                            
                            # First try: direct child
                            for child in wasel_elem:
                                if child.tag.endswith(xml_field):
                                    elem = child
                                    break
                            
                            # Second try: find with tag name
                            if elem is None:
                                elem = wasel_elem.find(xml_field)
                            
                            # Third try: find with namespace-aware search
                            if elem is None:
                                elem = wasel_elem.find(f'.//{xml_field}')
                            
                            if elem is not None and elem.text:
                                address_info[key] = elem.text.strip()
                                #logger.debug(f"Found {key}: {address_info[key]}")
                            else:
                                address_info[key] = ""
                                #logger.debug(f"Not found or empty: {key}")
                        
                        # Convert numeric fields
                        for field in ['building_number', 'additional_number', 'zip_code', 'unit_number']:
                            if address_info.get(field):
                                try:
                                    address_info[f'{field}_numeric'] = int(address_info[field])
                                except ValueError:
                                    address_info[f'{field}_numeric'] = 0
                            else:
                                address_info[f'{field}_numeric'] = 0
                        
                        ##logger.info(f"Successfully parsed address for: {address_info.get('full_name', 'Unknown')}")
                    else:
                        #logger.warning("WaselAddress element not found in response")
                        address_info['message'] = 'No WaselAddress element found in response'
                else:
                    #logger.warning("getIndividualWaselAddressResponseDetailObject element not found")
                    address_info['message'] = 'Response detail object not found'
            else:
                #logger.warning("GetIndividualWaselAddressResult element not found")
                address_info['message'] = 'Response result element not found'
        else:
            #logger.warning("GetIndividualWaselAddressResponse element not found")
            address_info['message'] = 'Response element not found in SOAP response'
        
        # Determine final status
        if address_info['record_found'] and address_info['has_address']:
            return {
                "status": "success",
                "message": address_info['message'],
                "address_info": address_info,
                "raw_response": soap_response_xml
            }
        else:
            return {
                "status": "error",
                "error_message": address_info['message'],
                "error_type": "no_data",
                "address_info": address_info,
                "raw_response": soap_response_xml
            }
        
    except ET.ParseError as e:
        #logger.error(f"XML parsing error in National Address response: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Invalid XML response from National Address service: {str(e)}",
            "error_type": "xml_parsing_error",
            "raw_response": soap_response_xml
        }
    
    except Exception as e:
        #logger.error(f"Error parsing National Address SOAP response: {str(e)}")
        return {
            "status": "error",
            "error_message": f"Failed to parse National Address response: {str(e)}",
            "error_type": "parsing_error",
            "raw_response": soap_response_xml
        }


def get_oracle_connection():
    """
    Create a direct connection to the external Oracle Banner database using thick mode.
    
    Returns:
        Oracle connection object or None if connection fails
    """
    try:
        import os
        import platform
        
        # Set Oracle environment variables BEFORE importing oracledb based on OS
        system = platform.system()
        
        if system == "Windows":
            # Windows configuration
            oracle_home = r'C:\oracle\instantclient_23_8'
            os.environ['ORACLE_HOME'] = oracle_home
            if oracle_home not in os.environ.get('PATH', ''):
                os.environ['PATH'] = os.environ['PATH'] + f';{oracle_home}'
            oracle_lib_dir = oracle_home
        else:
            # macOS/Linux configuration
            # Try common locations for Oracle Instant Client
            possible_paths = [
                '/opt/oracle/instantclient_23_8',
                '/opt/oracle/instantclient_21_8',
                '/opt/oracle/instantclient_19_8',
                '/usr/local/oracle/instantclient_23_8',
                '/usr/local/oracle/instantclient_21_8',
                '/usr/local/oracle/instantclient_19_8',
                '/usr/lib/oracle/instantclient_23_8',
                '/usr/lib/oracle/instantclient_21_8',
                '/usr/lib/oracle/instantclient_19_8',
                '/opt/instantclient_23_8',
                '/opt/instantclient_21_8',
                '/opt/instantclient_19_8',
                '/Applications/instantclient_23_8',
                '/Applications/instantclient_21_8',
                '/usr/local/lib/instantclient',
                # Check if Oracle client is in system PATH
                '/usr/local/lib',
                '/usr/lib'
            ]
            
            oracle_lib_dir = None
            for path in possible_paths:
                if os.path.exists(path):
                    # Check if this path contains Oracle libraries
                    if any(os.path.exists(os.path.join(path, lib)) for lib in ['libclntsh.dylib', 'libclntsh.so', 'libclntsh.so.19.1']):
                        oracle_lib_dir = path
                        os.environ['ORACLE_HOME'] = path
                        if path not in os.environ.get('PATH', ''):
                            os.environ['PATH'] = os.environ['PATH'] + f':{path}'
                        break
        
        import oracledb
        
        # Get Oracle database connection parameters from environment
        # Check if we should use test database for Banner operations
     
            # Use production database configuration
        host = config('BANNER_DB_HOST')
        port = config('BANNER_DB_PORT')
        service_name = config('BANNER_DB_SERVICE_NAME', default='pprd')
        user = config('BANNER_DB_USER', default='seutools_admsn')
        password = config('BANNER_DB_PASSWORD', default='Seu$123321')
        print(f"🏭 Using Banner PRODUCTION database: {host}:{port}/{service_name}")

        # print(host, port, service_name, user, password)
        
        # Create connection string
        dsn = f"{host}:{port}/{service_name}"
        
        ##logger.info(f"Attempting to connect to Oracle database: {host}:{port}/{service_name}")
        
        # Initialize thick mode to support older password verifiers (required for old DB servers)
        try:
            if oracle_lib_dir and os.path.exists(oracle_lib_dir):
                # Try to initialize with explicit lib_dir path first
                oracledb.init_oracle_client(lib_dir=oracle_lib_dir)
                print(f"✅ Oracle thick mode initialized successfully with path: {oracle_lib_dir}")
            else:
                # Try default initialization (Oracle client in system PATH)
                oracledb.init_oracle_client()
                print("✅ Oracle thick mode initialized successfully with system default")
        except Exception as init_error:
            # For development/testing, try thin mode as fallback
            print(f"⚠️  Oracle thick mode initialization failed: {init_error}")
            print(f"🔍 System: {system}, Checked paths: {', '.join([p for p in possible_paths if os.path.exists(p)])}")
            if oracle_lib_dir:
                print(f"📁 Oracle lib dir found: {oracle_lib_dir}")
            else:
                print("❌ No Oracle Instant Client installation found")
            print("💡 Note: Install Oracle Instant Client for better compatibility with older databases")
            print("📖 See oracle_setup_guide.md for installation instructions")
            # Continue with thin mode - may work for newer Oracle databases
        
        # Create connection using thick mode (or thin mode if thick failed)
        connection = oracledb.connect(
            user=user,
            password=password,
            dsn=dsn
        )
        
        # print("Successfully connected to Oracle Banner database")
        return connection
        
    except ImportError:
        #logger.error("oracledb library not installed. Install with: pip install oracledb")
        return None
    except Exception as e:
        print(f"Failed to connect to Oracle Banner database: {str(e)}")
        
        # If Oracle client is missing, provide installation guidance
        if "Oracle thick mode" in str(e) or "libclntsh" in str(e) or "DPI-1047" in str(e):
            print("💡 Oracle Instant Client is required for thick mode connection")
            print("📋 To install Oracle Instant Client on macOS:")
            print("   1. Run: ./install_oracle_client.sh")
            print("   2. Or download manually from Oracle website")
            print("   3. Extract to /opt/oracle/instantclient_XX_X/")
        
        return None


def get_banner_connection():
    """
    Create a direct connection to the Banner Oracle database.
    
    Returns:
        Oracle connection object or None if connection fails
    """
    try:
        import os
        import platform
        
        # Set Oracle environment variables BEFORE importing oracledb based on OS
        system = platform.system()
        
        if system == "Windows":
            # Windows configuration
            oracle_home = r'C:\oracle\instantclient_23_8'
            os.environ['ORACLE_HOME'] = oracle_home
            if oracle_home not in os.environ.get('PATH', ''):
                os.environ['PATH'] = os.environ['PATH'] + f';{oracle_home}'
            oracle_lib_dir = oracle_home
        else:
            # macOS/Linux configuration
            # Try common locations for Oracle Instant Client
            possible_paths = [
                '/opt/oracle/instantclient_23_8',
                '/opt/oracle/instantclient_21_8',
                '/opt/oracle/instantclient_19_8',
                '/usr/local/oracle/instantclient_23_8',
                '/usr/local/oracle/instantclient_21_8',
                '/usr/local/oracle/instantclient_19_8',
                '/usr/lib/oracle/instantclient_23_8',
                '/usr/lib/oracle/instantclient_21_8',
                '/usr/lib/oracle/instantclient_19_8',
                '/opt/instantclient_23_8',
                '/opt/instantclient_21_8',
                '/opt/instantclient_19_8',
                '/Applications/instantclient_23_8',
                '/Applications/instantclient_21_8',
                '/usr/local/lib/instantclient',
                # Check if Oracle client is in system PATH
                '/usr/local/lib',
                '/usr/lib'
            ]
            
            oracle_lib_dir = None
            for path in possible_paths:
                if os.path.exists(path):
                    # Check if this path contains Oracle libraries
                    if any(os.path.exists(os.path.join(path, lib)) for lib in ['libclntsh.dylib', 'libclntsh.so', 'libclntsh.so.19.1']):
                        oracle_lib_dir = path
                        os.environ['ORACLE_HOME'] = path
                        if path not in os.environ.get('PATH', ''):
                            os.environ['PATH'] = os.environ['PATH'] + f':{path}'
                        break
        
        import oracledb
        
        # Get Oracle database connection parameters from environment
        # Check if we should use test database for Banner operations
       
        # Use production database configuration
        host = config('BANNER_DB_HOST')
        port = config('BANNER_DB_PORT')
        service_name = config('BANNER_DB_SERVICE_NAME', default='pprd')
        user = config('BANNER_DB_USER', default='seutools_admsn')
        password = config('BANNER_DB_PASSWORD', default='Seu$123321')
        print(f"🏭 BANNER STUDENT ADMISSION: Using PRODUCTION database: {host}:{port}/{service_name}")

        # Create connection string
        dsn = f"{host}:{port}/{service_name}"
        
        ##logger.info(f"Attempting to connect to Oracle database: {host}:{port}/{service_name}")
        
        # Initialize thick mode to support older password verifiers (required for old DB servers)
        try:
            if oracle_lib_dir and os.path.exists(oracle_lib_dir):
                # Try to initialize with explicit lib_dir path first
                oracledb.init_oracle_client(lib_dir=oracle_lib_dir)
                print(f"✅ Oracle thick mode initialized successfully with path: {oracle_lib_dir}")
            else:
                # Try default initialization (Oracle client in system PATH)
                oracledb.init_oracle_client()
                print("✅ Oracle thick mode initialized successfully with system default")
        except Exception as init_error:
            # For development/testing, try thin mode as fallback
            print(f"⚠️  Oracle thick mode initialization failed: {init_error}")
            print(f"🔍 System: {system}, Checked paths: {', '.join([p for p in possible_paths if os.path.exists(p)])}")
            if oracle_lib_dir:
                print(f"📁 Oracle lib dir found: {oracle_lib_dir}")
            else:
                print("❌ No Oracle Instant Client installation found")
            print("💡 Note: Install Oracle Instant Client for better compatibility with older databases")
            print("📖 See oracle_setup_guide.md for installation instructions")
            # Continue with thin mode - may work for newer Oracle databases
        
        # Create connection using thick mode (or thin mode if thick failed)
        connection = oracledb.connect(
            user=user,
            password=password,
            dsn=dsn
        )
        
        # print("Successfully connected to Oracle Banner database")
        return connection
        
    except ImportError:
        #logger.error("oracledb library not installed. Install with: pip install oracledb")
        return None
    except Exception as e:
        #logger.error(f"Failed to connect to Oracle Banner database: {e}")
        print(f"❌ Failed to connect to Banner database: {e}")
        return None


def execute_oracle_stored_procedure(procedure_name, in_parameters, out_parameters):
    """
    Execute a stored procedure on the external Oracle Banner database.
    
    Args:
        procedure_name: Name of the stored procedure to execute
        in_parameters: Dictionary of IN parameters where:
            - Keys are parameter names
            - Values are the actual values to pass (string/int/etc)
        out_parameters: List of OUT parameter names that will receive output values
    
    Returns:
        Dict containing execution results or error information
    """
    import oracledb
    import datetime
    connection = None
    cursor = None
    
    try:
        # Get database connection
        connection = get_oracle_connection()
        if not connection:
            return {
                "status": "error",
                "error_message": "Could not establish connection to Banner database. Oracle Instant Client may not be installed or configured properly.",
                "error_type": "connection_error",
                "suggestion": "Install Oracle Instant Client or check database configuration"
            }
        
        # Create cursor
        cursor = connection.cursor()
        
        # Initialize parameters
        if in_parameters is None:
            in_parameters = {}
        if out_parameters is None:
            out_parameters = []
        
        # Prepare parameter list for the stored procedure
        param_list = []
        param_vars = {}
        all_param_names = []
        
        # Add IN parameters first (all parameters in order)
        for param_name, param_value in in_parameters.items():
            param_list.append(param_value)
            all_param_names.append(param_name)
        
        # Add OUT parameters
        for param_name in out_parameters:
            if param_name == 'o_result':
                # Create cursor variable for SYS_REFCURSOR
                var = cursor.var(oracledb.CURSOR)
            else:
                # Create string variable for regular OUT parameters
                var = cursor.var(str)
            
            param_list.append(var)
            param_vars[param_name] = var
            all_param_names.append(param_name)
        print('excuting stored procedure', procedure_name)
        # Execute stored procedure
        result = cursor.callproc(procedure_name, param_list)
        print('result', result)
        # Extract OUT parameter values
        output_values = {}
       
        # Handle the callproc result (for procedures that return values directly)
        if result and len(result) > len(in_parameters):
            # Extract OUT parameter values from the result list
            out_param_start_index = len(in_parameters)
            for i, param_name in enumerate(out_parameters):
                if out_param_start_index + i < len(result):
                    raw_value = result[out_param_start_index + i]
                    # Convert datetime objects to strings for JSON serialization
                    if isinstance(raw_value, (datetime.datetime, datetime.date)):
                        output_values[param_name] = raw_value.isoformat()
                    else:
                        output_values[param_name] = raw_value
        
        # Handle OUT parameter variables (for complex cursor results)
        for param_name in out_parameters:
            if param_name in param_vars:
                if param_name == 'o_result':
                    # Handle cursor OUT parameter (SYS_REFCURSOR)
                    cursor_var = param_vars[param_name]
                    cursor_result = cursor_var.getvalue()
                    if cursor_result:
                        # Fetch all rows from the cursor
                        rows = cursor_result.fetchall()
                        columns = [desc[0] for desc in cursor_result.description]
                        result_data = []
                        for row in rows:
                            row_dict = dict(zip(columns, row))
                            # Convert datetime objects to strings for JSON serialization
                            for key, value in row_dict.items():
                                if isinstance(value, (datetime.datetime, datetime.date)):
                                    row_dict[key] = value.isoformat()
                            result_data.append(row_dict)
                        output_values[param_name] = result_data
                    else:
                        output_values[param_name] = []
                else:
                    # Handle regular string OUT parameters from variables
                    if param_name not in output_values:  # Only if not already extracted from result
                        out_value = param_vars[param_name].getvalue()
                        # Convert datetime objects to strings for JSON serialization
                        if isinstance(out_value, (datetime.datetime, datetime.date)):
                            output_values[param_name] = out_value.isoformat()
                        else:
                            output_values[param_name] = out_value if out_value else ""
        
        return {
            "status": "success",
            "procedure_name": procedure_name,
            "output_parameters": output_values,
            "raw_result": result,  # Include raw result for debugging/compatibility
            "message": f"Stored procedure {procedure_name} executed successfully"
        }
        
    except Exception as e:
        error_message = f"Error executing stored procedure {procedure_name}: {str(e)}"
        print(f"❌ BANNER PUSH ERROR: {error_message}")
        
        # Log parameters for debugging
        print("📋 Parameters being passed to Oracle:")
        param_index = 1
        for param_name, param_value in in_parameters.items():
            print(f"   [{param_index}] {param_name}: {param_value} ({type(param_value)}) - IN")
            param_index += 1
        for param_name in out_parameters:
            print(f"   [{param_index}] {param_name}: OUT parameter")
            param_index += 1
        
        # Try to get more specific Oracle error information
        oracle_error_code = None
        oracle_error_message = None
        
        try:
            # Check if it's an Oracle-specific error
            if hasattr(e, 'code'):
                oracle_error_code = e.code
            if hasattr(e, 'message'):
                oracle_error_message = e.message
            elif hasattr(e, 'args') and e.args:
                oracle_error_message = str(e.args[0])
                
            print(f"🔍 Oracle Error Code: {oracle_error_code}")
            print(f"🔍 Oracle Error Message: {oracle_error_message}")
            
            # # Log parameter details for debugging
            # if parameters:
            #     print("🔍 Parameters that caused the error:")
            #     for param_name, param_value in parameters.items():
            #         if param_value is not None:
            #             print(f"   {param_name}: {repr(param_value)} (type: {type(param_value)})")
                        
        except Exception as debug_e:
            print(f"Could not extract detailed Oracle error info: {debug_e}")
        
        return {
            "status": "error",
            "error_message": error_message,
            "error_type": "execution_error",
            "procedure_name": procedure_name,
            "oracle_error_code": oracle_error_code,
            "oracle_error_message": oracle_error_message
        }
        
    finally:
        # Clean up resources
        if cursor:
            try:
                cursor.close()
            except:
                pass
        
        if connection:
            try:
                connection.close()
            except:
                                pass






# Backward compatibility wrapper for the old method signature
def extract_simple_result(oracle_result, expected_params=None):
    """
    Helper function to extract simple results from Oracle stored procedure calls.
    
    Args:
        oracle_result: Result from execute_oracle_stored_procedure
        expected_params: List of expected parameter names for simple results
    
    Returns:
        Simplified result structure or original if complex
    """
    if oracle_result.get('status') != 'success':
        return oracle_result
    
    output_params = oracle_result.get('output_parameters', {})
    raw_result = oracle_result.get('raw_result', [])
    
    # Check if this looks like a simple result (no cursor data)
    has_cursor_data = any(
        isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict)
        for value in output_params.values()
    )
    
    if not has_cursor_data and expected_params and len(raw_result) >= len(expected_params):
        # Extract simple values from raw result
        simple_result = {}
        for i, param_name in enumerate(expected_params):
            if i < len(raw_result):
                simple_result[param_name] = raw_result[i]
        
        return {
            "status": "success",
            "data": simple_result,
            "raw_values": raw_result,
            "message": oracle_result.get('message', 'Success')
        }
    
    # Return original result for complex data
    return oracle_result


def execute_oracle_stored_procedure_old(procedure_name, parameters=None):
    """
    Backward compatibility wrapper for the old execute_oracle_stored_procedure method.
    
    Args:
        procedure_name: Name of the stored procedure to execute
        parameters: Dictionary where None values are OUT parameters, others are IN parameters
    
    Returns:
        Dict containing execution results or error information
    """
    if parameters is None:
        parameters = {}
    
    # Separate IN and OUT parameters
    in_parameters = {}
    out_parameters = []
    
    for param_name, param_value in parameters.items():
        if param_value is None:
            out_parameters.append(param_name)
        else:
            in_parameters[param_name] = param_value
    
    # Call the new method
    return execute_oracle_stored_procedure(
        procedure_name=procedure_name,
        in_parameters=in_parameters,
        out_parameters=out_parameters
    )


def execute_oracle_function(function_name, parameters=None):
    """
    Execute an Oracle function and return the result.
    
    Args:
        function_name (str): Name of the Oracle function to execute (e.g., 'SEU_REP.F_GET_ELIGIBILITY')
        parameters (dict): Dictionary of parameters where:
            - Key is parameter name
            - Value is parameter value (for IN parameters)
            - None value indicates OUT parameter
    
    Returns:
        dict: Execution result with status, function result, and any output parameters
    """
    connection = None
    cursor = None
    
    try:
        connection = get_oracle_connection()
        # print('connection started', connection)
        if not connection:
            return {
                "status": "error",
                "error_message": "Could not establish connection to Banner database",
                "error_type": "connection_error"
            }
        cursor = connection.cursor()
        
        # Prepare function call
        if parameters:
            # Build parameter list for function call
            param_list = []
            param_vars = {}
            #output_vars = {}
            
           
            
            # Build function call SQL
            placeholders = ', '.join( par for par in parameters)
            sql = f"SELECT {function_name}({placeholders}) FROM DUAL"
            
            #   print('sql', sql)
            # Execute function
            cursor.execute(sql, param_list)
            result = cursor.fetchone()
            
            
            # Get function return value
            function_result = result[0] if result else None
            
            # Extract output parameter values
            output_values = {}
            for param_name, var in param_vars.items():
                output_values[param_name] = var.getvalue()
        else:
            # No parameters - simple function call
            sql = f"SELECT {function_name}() FROM DUAL"
            cursor.execute(sql)
            result = cursor.fetchone()
            function_result = result[0] if result else None
            output_values = {}
        
        return {
            "status": "success",
            "function_name": function_name,
            "result": function_result,
            "output_parameters": output_values,
            "message": f"Function {function_name} executed successfully"
        }
        
    except Exception as e:
        error_message = f"Error executing function {function_name}: {str(e)}"
        # print(error_message)
        
        return {
            "status": "error",
            "error_message": error_message,
            "error_type": "execution_error",
            "function_name": function_name
        }
        
    finally:
        # Clean up resources
        if cursor:
            try:
                cursor.close()
            except:
                pass
        
        if connection:
            try:
                connection.close()
            except:
                pass

def get_old_noor_recored(ssn):
    """
    Connect to SQL Server Noor database and test the connection.
    
    Args:
        ssn (str): Student Social Security Number
    
    Returns:
        dict: Connection status result
    """
    try:
       
        
        # Get Noor database configuration from .env file
        noor_host = config('NoorDB_host')  # 172.30.2.39\sqllive02
        noor_port = config('NoorDB_port', default='1433')  # Default SQL Server port
        noor_database = config('NoorDB_database')  # GHDB-Master
        noor_user = config('NoorDB_username')  # Addmission
        noor_password = config('NoorDB_password')
        
        # Check if configuration is available
        if not all([noor_host, noor_database, noor_user, noor_password]):
            missing_configs = []
            if not noor_host: missing_configs.append("NoorDB_host")
            if not noor_database: missing_configs.append("NoorDB_database")
            if not noor_user: missing_configs.append("NoorDB_username")
            if not noor_password: missing_configs.append("NoorDB_password")
            
            print(f"FAIL - Missing Noor DB configuration: {', '.join(missing_configs)}")
            return {
                "status": "error",
                "error_message": f"Missing Noor DB configuration: {', '.join(missing_configs)}"
            }
        
        # Build connection string for SQL Server (handle server\instance format)
        # Your host is 172.30.2.39\sqllive02 (server\instance)
        if '\\' in noor_host:
            # Server\Instance format - don't add port
            server_string = noor_host
        else:
            # Just server name - add port
            server_string = f"{noor_host},{noor_port}"
        
        print(f"Attempting to connect to Noor SQL Server database: {server_string}/{noor_database}")
        
        # Try different SQL Server drivers in order of preference
        drivers = pyodbc.drivers()
        driver_options = [
            "ODBC Driver 18 for SQL Server",
            "ODBC Driver 17 for SQL Server", 
            "ODBC Driver 13 for SQL Server",
            "ODBC Driver 11 for SQL Server",
            "SQL Server Native Client 11.0",
            "SQL Server Native Client 10.0",
            "SQL Server"
        ]
        
        connection = None
        driver_used = None
        
        for driver in driver_options:
            if driver in drivers:
                try:
                    connection_string = (
                        f"DRIVER={{{driver}}};"
                        f"SERVER={server_string};"
                        f"DATABASE={noor_database};"
                        f"UID={noor_user};"
                        f"PWD={noor_password};"
                        f"TrustServerCertificate=yes;"
                        f"Encrypt=no;"
                    )
                    
                    connection = pyodbc.connect(connection_string, timeout=30)
                    driver_used = driver
                    break
                    
                except Exception:
                    continue
        
        if not connection:
            available_drivers = [d for d in driver_options if d in drivers]
            raise Exception(f"Failed to connect with any available SQL Server driver. Available: {available_drivers}")
        
        # Test the connection with a simple query
        cursor = connection.cursor()
        query = f"SELECT TOP(1) * from dbo.Univ_Master where Student_Identity like '%{ssn}%'"

        #print('query', query)
        cursor.execute(query)
        
        result = cursor.fetchone()
        
        # Close connection
        cursor.close()
        connection.close()
        if result:
            return {"data": {
                        "StudentBasicInfo": {
                            "NameAr": result[4] if result[4] else "غير متوفر",
                            "StudentNameEn": result[5] if result[5] else "غير متوفر",
                            "Gender":  "غير متوفر"
                        },
                        "CertificationDetails": {
                            "StudyTypeAr": result[21] if result[21] else "غير متوفر",
                            "StudyTypeEn": "غير متوفر",
                            "EducationalLevel": "المرحلة الثانوية",
                            "EducationTypeAr":'غير متوفر',
                            "EducationTypeEn": 'غير متوفر',
                            "MajorCode": 'غير متوفر',
                            "MajorTypeAr": result[15] if result[15] else "المسار الأدبي",
                            "MajorTypeEn": result[16] if result[16] else "المسار الأدبي",
                            "GPA": result[31] if result[31] else "غير متوفر",
                            "GPATypeAr": "نسبة مئوية",
                            "GPATypeEn": "Percentage",
                            "GPAMAX": '100',
                            "GPADegreeAr": "غير متوفر",
                            "GPADegreeEn": "غير متوفر",
                            "CertificationHijriYear":'غير متوفر',
                            "CertificationGregYear": 'غير متوفر',
                            
                        }
                    }
                }
        
        
           
        else:
            print("FAIL - Connection test query failed")
            return {
                "status": "error",
                "error_message": "Connection test query failed"
            }
        
    except pyodbc.Error as e:
        error_msg = f"SQL Server connection error: {str(e)}"
        print(f"FAIL - {error_msg}")
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "sql_server_error"
        }
        
    except Exception as e:
        error_msg = f"Unexpected error connecting to Noor database: {str(e)}"
        print(f"FAIL - {error_msg}")
        return {
            "status": "error",
            "error_message": error_msg,
            "error_type": "connection_error"
        }


def create_standardized_response(status="success", data=None, message=None, error=None, status_code=200):
    """
    Create a standardized API response format
    
    Args:
        status (str): Response status ('success', 'error', 'warning')
        data (any): Response data
        message (str): Success or info message
        error (str): Error message
        status_code (int): HTTP status code
    
    Returns:
        dict: Standardized response dictionary
    """
    response = {
        "status": status,
        "timestamp": time.time(),
        "status_code": status_code
    }
    
    if status == "success":
        if data is not None:
            response["data"] = data
        if message:
            response["message"] = message
    elif status == "error":
        if error:
            response["error"] = error
        if message:
            response["message"] = message
    else:  # warning or other statuses
        if data is not None:
            response["data"] = data
        if message:
            response["message"] = message
        if error:
            response["error"] = error
    
    return response


def validate_required_fields(data, required_fields):
    """
    Validate that all required fields are present in the data
    
    Args:
        data (dict): Input data to validate
        required_fields (list): List of required field names
    
    Returns:
        tuple: (is_valid: bool, missing_fields: list, error_message: str)
    """
    missing_fields = []
    
    for field in required_fields:
        if field not in data or data[field] is None or (isinstance(data[field], str) and not data[field].strip()):
            missing_fields.append(field)
    
    if missing_fields:
        error_message = f"Missing required fields: {', '.join(missing_fields)}"
        return False, missing_fields, error_message
    
    return True, [], None


def validate_national_id(national_id):
    """
    Validate Saudi National ID or Iqama number format
    
    Args:
        national_id (str): National ID to validate
    
    Returns:
        tuple: (is_valid: bool, error_message: str)
    """
    if not national_id:
        return False, "National ID is required"
    
    if not isinstance(national_id, str):
        return False, "National ID must be a string"
    
    national_id = national_id.strip()
    
    if not national_id.isdigit():
        return False, "National ID must contain only digits"
    
    if len(national_id) != 10:
        return False, "National ID must be exactly 10 digits"
    
    # Basic validation for Saudi National ID format
    if national_id.startswith('1') or national_id.startswith('2'):
        return True, None
    else:
        return False, "National ID must start with 1 (Saudi) or 2 (Non-Saudi)"


def validate_mobile_number(mobile):
    """
    Validate mobile number format
    
    Args:
        mobile (str): Mobile number to validate
    
    Returns:
        tuple: (is_valid: bool, error_message: str, formatted_mobile: str)
    """
    if not mobile:
        return False, "Mobile number is required", None
    
    if not isinstance(mobile, str):
        return False, "Mobile number must be a string", None
    
    mobile = mobile.strip()
    
    if not mobile.isdigit():
        return False, "Mobile number must contain only digits", None
    
    # Remove country code if present
    if mobile.startswith('966'):
        mobile = mobile[3:]
    elif mobile.startswith('+966'):
        mobile = mobile[4:]
    
    # Saudi mobile numbers should be 9 digits (5xxxxxxxx)
    if len(mobile) != 9:
        return False, "Mobile number must be 9 digits (without country code)", None
    
    if not mobile.startswith('5'):
        return False, "Saudi mobile numbers must start with 5", None
    
    # Return with country code
    formatted_mobile = f"966{mobile}"
    return True, None, formatted_mobile


def validate_email(email):
    """
    Validate email format
    
    Args:
        email (str): Email to validate
    
    Returns:
        tuple: (is_valid: bool, error_message: str)
    """
    import re
    
    if not email:
        return False, "Email is required"
    
    if not isinstance(email, str):
        return False, "Email must be a string"
    
    email = email.strip()
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    return True, None

# History and logging utils



def create_api_history_record(endpoint, 
                              status_type, 
                              processing_time=None, 
                              result=None, 
                              error_message=None, 
                              requester=None, 
                              processing_method=None):
  
    history_enabled = ConfigurationManager.is_enabled('history.enabled', default=True)
    
    if not history_enabled:
        return None
    
    # Get requester name if not provided
    if requester is None:
        from .utils import get_requester_name
        # This is a fallback, ideally requester should be passed
        requester = 'Unknown' 
    
    return APIRequestHistory.objects.create(
        user=None,  # No user authentication
        requester=requester,
        endpoint=endpoint,
        status=status_type,
        processing_time=f"{processing_time:.2f}" if processing_time is not None else None,
        processing_method=processing_method,
        result=json.dumps(result) if result else None,
        error_message=error_message
    )


def get_history_context(request):

    history_enabled = ConfigurationManager.is_enabled('history.enabled', default=True)
    requester_name = None
    
    if history_enabled:
        from .utils import get_requester_name
        requester_name = get_requester_name(request)
    
    return history_enabled, requester_name


# Simple Logging Helper Functions
def log_info(message):
    """Log INFO level message if logging is enabled"""
    _write_log('INFO', message)

def log_warning(message):
    """Log WARNING level message if logging is enabled"""
    _write_log('WARNING', message)

def log_error(message):
    """Log ERROR level message if logging is enabled"""
    _write_log('ERROR', message)

def _write_log(level, message):
    """
    Write log message if logging is enabled in configuration
    
    Args:
        level (str): Log level (INFO, WARNING, ERROR)
        message (str): Log message
    """
    try:
        # Check if logging is enabled in configuration
        logging_enabled = ConfigurationManager.get_config('logging.enabled', default=True)
        if not logging_enabled:
            return
        
        # Get configured log level
        configured_level = ConfigurationManager.get_config('logging.level', default='INFO')
        
        # Check if current level should be logged
        level_hierarchy = {'DEBUG': 10, 'INFO': 20, 'WARNING': 30, 'ERROR': 40, 'CRITICAL': 50}
        if level_hierarchy.get(level, 20) < level_hierarchy.get(configured_level, 20):
            return
        
        # Create logger
        logger = logging.getLogger('apis')
        
        # No user info needed since authentication is removed
        formatted_message = message
        
        # Write log based on level
        if level == 'INFO':
            logger.info(formatted_message)
        elif level == 'WARNING':
            logger.warning(formatted_message)
        elif level == 'ERROR':
            logger.error(formatted_message)
        else:
            logger.info(formatted_message)
            
    except Exception as e:
        # Fail silently if logging fails
        pass


