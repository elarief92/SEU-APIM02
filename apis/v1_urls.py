"""
URL configuration for APIs app.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
   

# Create DRF router
router = DefaultRouter()


urlpatterns = [
   
    
    # General utilities endpoints
    path('extract-GOSI_subscription/', views.ExtractSubscriptionMonthsView.as_view(), name='extract-GOSI_subscription'),
    path('AI_extract-GOSI_subscription/', views.ExtractSubscriptionMonthsByAIView.as_view(), name='AI_extract-GOSI_subscription'),
     # Web interface compatibility endpoint
    path('process-certificate/', views.process_certificate, name='process-certificate'),
    
    path('sms/', views.SMSAPIView.as_view(), name='sms-api'),
   

   #Validation endpoints
    # Disability API endpoint
    path('disability/', views.DisabilityAPIView.as_view(), name='disability-api'),
    # National Address API endpoint
    path('national-address/', views.NationalAddressAPIView.as_view(), name='national-address-api'),
    # School Student Record API (direct endpoint)
    path('noor/', views.NoorAPIView.as_view(), name='noor-api'),
    # Qiyas Exam Result API (direct endpoint)
  
    path('qudurat/', views.QudaratAPIView.as_view(), name='qudurat-api'),
     # STEP Exam Result API (direct endpoint)
    path('step/', views.STEPAPIView.as_view(), name='step-api'),
    # Social Security Indigent Inquiry API (direct endpoint)
    path('social-security/', views.SocialSecurityAPIView.as_view(), name='social-security-api'),
    # Qualifications API (direct endpoint)
    path('moahal/', views.MoahalAPIView.as_view(), name='moahal-api'),
    # Yaqeen Saudi API endpoint
    path('yaqeen/', views.YaqeenAPIView.as_view(), name='yaqeen'),

    # Banner Database Endpoints
    path('bachelor-eligibility/', views.BachelorEligibilityAPIView.as_view(), name='bachelor-eligibility-api'),

    


    # EJADAH ERP 
    path('erp/employee-profile/', views.EmployeeProfileAPIView.as_view(), name='erp-employee-profile-api'),
    path('erp/employee-profile/optimized/', views.ATSGetInfoOptimized.as_view()),
    path('erp/employee-profile/optimized-production/', views.ATSGetInfoOptimizedProduction.as_view()),
    
    #Request by Bassem Alhazmi
    path('erp/PR/create/', views.PRCreateAPIView.as_view(), name='erp-pr-create-api'),
    path('erp/PR/request/details/', views.PRRequestDetailsAPIView.as_view(), name='erp-pr-request-details-api'),
    path('erp/PR/attachement/add/', views.PRAttachementAPIView.as_view(), name='erp-pr-attachement-add-api'),
    path('erp/PR/cancel/', views.PRCancelAPIView.as_view(), name='erp-pr-cancel-api'),
    path('erp/PR/work-confirmation/create/', views.PRWorkConfirmationCreateAPIView.as_view(), name='erp-pr-work-confirmation-create-api'),

    #ATS ERP APIs
    path('ats/erp/generate/seq/report/', views.ATSGenerateSeqReportAPIView.as_view()),
    path('ats/erp/report/recored/create/', views.ATSCreateReportAPIView.as_view()),
    path('ats/erp/report/show/', views.ATSShowReportAPIView.as_view()),

    # General ERP APIs
    path('erp/report/types/', views.ShowReportTypesAPIView.as_view()),
    path('erp/report/show/', views.ShowReportAPIView.as_view()),

    # leave ERP APIs
     path('ats/erp/leave/types/', views.ATSLeaveTypesAPIView.as_view()),
     path('ats/erp/leave/balance/', views.ATSLeaveBalanceAPIView.as_view()),
     path('ats/erp/leave/workflow/details/', views.ATSLeaveWorkflowDetailsAPIView.as_view()),
     path('ats/erp/leave/substitutes/', views.ATSSubstitutesAPIView.as_view()),
     path('ats/erp/leave/request/e-service/', views.ATSRequestEServiceAPIView.as_view()),
     path('ats/erp/leave/request/cancel/', views.ATSRequestCancelAPIView.as_view()),
     path('ats/erp/leave/workflow/status/', views.ATSLeaveWorkflowStatusAPIView.as_view()),
    
    # Banner 
    path('student-profile/', views.StudentProfileAPIView.as_view(), name='student-profile-api'),
    path('student-info/', views.StudentInfoAPIView.as_view(), name='student-info-api'),
 
    path('update-student-mobile/', views.StudentMobileAPIView.as_view(), name='student-mobile-api'),
    path('student/transcript/q/', views.StudentTranscriptAPIView.as_view(), name='student-transcript-api'),
    path('student/transcript/', views.StudentTranscriptAPIViewSP.as_view(), name='student-transcript-api-sp'),
    path('student/sechdule/', views.StudentScheduleAPIView.as_view(), name='student-schedule-api'),
    path('student/absences/', views.StudentAbsencesAPIView.as_view(), name='student-absences-api'),
    path('student/absences/excuse/', views.StudentAbsencesExcuseAPIView.as_view(), name='student-absences-excuse-api'),
    path('student/absences/excuse/submit/', views.StudentAbsencesExcuseSubmitAPIView.as_view(), name='student-absences-excuse-submit-api'),
    path('student/tuition/statement/', views.StudentTuitionStatementAPIView.as_view(), name='student-tuition-statement-api'),
    path('student/verification/statement/', views.StudentVerificationStatementAPIView.as_view(), name='student-verification-statement-api'),
    path('student/study-duration/statement/', views.StudentStudyDurationStatementAPIView.as_view(), name='student-study-duration-statement-api'),
    path('student/final-admission/statement/', views.StudentFinalAdmissionStatementAPIView.as_view(), name='student-final-admission-statement-api'),
    path('student/external-transfer/statement/', views.StudentExternalTransferStatementAPIView.as_view(), name='student-external-transfer-statement-api'),
    path('student/medical-report/statement/', views.StudentMedicalReportStatementAPIView.as_view(), name='student-medical-report-statement-api'),
    path('student/FB-non-entitlement/statement/', views.StudentFBNonEntitlementStatementAPIView.as_view(), name='student-FB-non-entitlement-statement-api'),
    path('student/final-exams/statement/', views.StudentFinalExamsStatementAPIView.as_view(), name='student-final-exams-statement-api'),

    path('banner/campuses/', views.BannerCampusesAPIView.as_view(), name='banner-campuses-api'),
    path('banner/programs/', views.BannerProgramsAPIView.as_view(), name='banner-programs-api'),
    path('banner/semesters/', views.BannerSemestersAPIView.as_view(), name='banner-semesters-api'),
    path('banner/departments/', views.BannerDepartmentsAPIView.as_view(), name='banner-departments-api'),
    

] 