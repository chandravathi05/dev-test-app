import os
import json
import time
import uuid
import hashlib
import logging
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from cryptography.fernet import Fernet

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('esignAndAgreementGenerationController')

ENCRYPTION_KEY = os.environ.get('DOC_ENC_KEY') or Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)

ERRORS = {
    'ERR_PRECONDITION_KYC_INCOMPLETE': 'KYC incomplete or documents missing/expired',
    'ERR_POLICY_VIOLATION': 'Policy violation detected: {reason}',
    'ERR_TEMPLATE_NOT_FOUND': 'No approved template found for product/region/segment',
    'ERR_FINANCIAL_MISMATCH': 'Computed financials mismatch with approved offer',
    'ERR_ESIGN_INIT_FAIL': 'Failed to initiate e-sign provider request',
    'ERR_ESIGN_CALLBACK_INVALID': 'Invalid e-sign callback or signature verification failed',
    'ERR_MANDATE_NOT_CONFIRMED': 'Required e-mandate not confirmed',
    'ERR_DOC_STORE_FAIL': 'Failed to persist document to repository',
    'ERR_EXTERNAL_RETRY_EXHAUSTED': 'External system unreachable after retries; escalated to operations',
    'ERR_UNAUTHORIZED': 'User not authorized to perform this action'
}

AUTHORIZED_ROLES = {'OperationsUser', 'Underwriter', 'SalesUser', 'SystemAdministrator'}
MUTATION_ALLOWED_ROLES = {'OperationsUser', 'Underwriter', 'SalesUser', 'SystemAdministrator'}
MAKER_CHECKER_REQUIRED = {'TemplateOverride', 'ParameterOverride'}

config = {
    'financial_tolerance_pct': 0.5,
    'external_max_retries': 3,
    'external_backoff_factor': 1.5,
    'esign_tls_required': True,
    'mandate_required_for_disbursal': True
}

applications: Dict[str, Dict[str, Any]] = {}
offers: Dict[str, Dict[str, Any]] = {}
kyc_checklists: Dict[str, Dict[str, Any]] = {}
templates_store: Dict[str, List[Dict[str, Any]]] = {}
document_repository: Dict[str, Dict[str, Any]] = {}
audits: List[Dict[str, Any]] = []
policy_store: Dict[str, Any] = {}
consents_store: Dict[str, Dict[str, bool]] = {}
users: Dict[str, Dict[str, Any]] = {}
idempotency_store: Dict[str, Any] = {}
e_sign_provider_store: Dict[str, Dict[str, Any]] = {}
e_mandate_store: Dict[str, Dict[str, Any]] = {}
notifications: List[Dict[str, Any]] = []
core_integration_store: List[Dict[str, Any]] = []
physical_tasks: Dict[str, Dict[str, Any]] = {}

lock = threading.Lock()

def _now_iso():
    return datetime.utcnow().isoformat() + 'Z'

def audit_log(event_type: str, application_id: str, user_id: Optional[str], details: dict) -> Dict[str, Any]:
    try:
        audit_id = str(uuid.uuid4())
        entry = {
            'audit_id': audit_id,
            'timestamp': _now_iso(),
            'event_type': event_type,
            'application_id': application_id,
            'user_id': user_id,
            'details': details
        }
        with lock:
            audits.append(entry)
        logger.info('AUDIT %s %s', audit_id, json.dumps({'event_type': event_type, 'application_id': application_id}))
        return {'logged': True, 'audit_id': audit_id}
    except Exception as e:
        logger.error('Audit log failed: %s', str(e))
        return {'logged': False, 'audit_id': ''}

def _mask_pii(data: str) -> str:
    if not data:
        return ''
    return data[:2] + '****' + data[-2:]

def _check_role(user_id: str) -> bool:
    user = users.get(user_id)
    if not user:
        return False
    return user.get('role') in AUTHORIZED_ROLES

def _validate_mutation_role(user_id: str) -> bool:
    user = users.get(user_id)
    if not user:
        return False
    return user.get('role') in MUTATION_ALLOWED_ROLES

def _retry_external(callable_fn, idempotency_key: Optional[str] = None):
    attempts = 0
    last_exc = None
    while attempts < config['external_max_retries']:
        try:
            result = callable_fn()
            if idempotency_key:
                with lock:
                    idempotency_store[idempotency_key] = result
            return result
        except TransientExternalError as te:
            last_exc = te
            attempts += 1
            sleep_for = (config['external_backoff_factor'] ** attempts)
            time.sleep(sleep_for)
            continue
        except PermanentExternalError as pe:
            raise pe
    raise ExternalRetriesExhausted(str(last_exc))

class TransientExternalError(Exception):
    pass

class PermanentExternalError(Exception):
    pass

class ExternalRetriesExhausted(Exception):
    pass

def validate_preconditions(application_id: str) -> Dict[str, Any]:
    errors = []
    app = applications.get(application_id)
    if not app:
        return {'ok': False, 'errors': ['Application not found']}
    status = app.get('status')
    if status not in ('Approved', 'OfferAccepted'):
        errors.append('Application status must be Approved or OfferAccepted')
    offer_id = app.get('offer_id')
    if not offer_id or offer_id not in offers:
        errors.append('Offer details missing')
    kyc = kyc_checklists.get(application_id, {})
    required_docs = kyc.get('required_documents', [])
    missing_docs = []
    for d in required_docs:
        doc = kyc.get('documents', {}).get(d)
        if not doc:
            missing_docs.append(d)
        else:
            exp = doc.get('expiry')
            if exp and datetime.fromisoformat(exp) < datetime.utcnow():
                missing_docs.append(d + ' (expired)')
    if missing_docs:
        errors.append(ERRORS['ERR_PRECONDITION_KYC_INCOMPLETE'])
        errors.extend(missing_docs)
    policy = policy_store.get(application_id, {})
    if policy.get('negative_list', False):
        errors.append(ERRORS['ERR_POLICY_VIOLATION'].format(reason='Negative list hit'))
    if policy.get('blacklisted_profession'):
        errors.append(ERRORS['ERR_POLICY_VIOLATION'].format(reason='Blacklisted profession'))
    if policy.get('pincode_restricted'):
        errors.append(ERRORS['ERR_POLICY_VIOLATION'].format(reason='Pin code restricted'))
    if policy.get('internal_exposure'):
        errors.append(ERRORS['ERR_POLICY_VIOLATION'].format(reason='Internal exposure/delinquency'))
    cons = consents_store.get(application_id, {})
    if not cons.get('bureau'):
        errors.append('Consent: bureau access missing')
    if not cons.get('data_usage'):
        errors.append('Consent: data usage missing')
    if not cons.get('esign'):
        errors.append('Consent: e-sign missing')
    if errors:
        return {'ok': False, 'errors': errors}
    return {'ok': True, 'errors': []}

def select_template(product_variant: str, customer_segment: str, region: str, offer_parameters: dict) -> Dict[str, Any]:
    key = f'{product_variant}:{customer_segment}'
    candidates = templates_store.get(key, [])
    if not candidates:
        return {'template_id': '', 'version': '', 'template_metadata': {}, 'error': ERRORS['ERR_TEMPLATE_NOT_FOUND']}
    regional = [t for t in candidates if t.get('region') == region and t.get('status') == 'Approved']
    if regional:
        chosen = sorted(regional, key=lambda x: x.get('version'), reverse=True)[0]
    else:
        global_tpls = [t for t in candidates if t.get('region') == 'GLOBAL' and t.get('status') == 'Approved']
        if not global_tpls:
            return {'template_id': '', 'version': '', 'template_metadata': {}, 'error': ERRORS['ERR_TEMPLATE_NOT_FOUND']}
        chosen = sorted(global_tpls, key=lambda x: x.get('version'), reverse=True)[0]
    return {'template_id': chosen['template_id'], 'version': chosen['version'], 'template_metadata': chosen}

def _compute_emi(principal: float, annual_rate_pct: float, tenure_months: int) -> float:
    if tenure_months == 0:
        return 0.0
    r = annual_rate_pct / 100.0 / 12.0
    if r == 0:
        return principal / tenure_months
    emi = principal * r / (1 - (1 + r) ** (-tenure_months))
    return round(emi, 2)

def populate_template(template_id: str, application_data: dict, offer_data: dict) -> Dict[str, Any]:
    if not template_id:
        return {'document': b'', 'checksum': '', 'rendered_fields': {}, 'error': ERRORS['ERR_TEMPLATE_NOT_FOUND']}
    principal = offer_data.get('amount')
    tenure = offer_data.get('tenure_months')
    annual_rate = offer_data.get('annual_rate_pct')
    computed_emi = _compute_emi(principal, annual_rate, tenure)
    offered_emi = offer_data.get('emi')
    tolerance_pct = config['financial_tolerance_pct']
    if offered_emi is None:
        offered_emi = computed_emi
    diff_pct = abs(computed_emi - offered_emi) / max(offered_emi, 1) * 100
    if diff_pct > tolerance_pct:
        return {'document': b'', 'checksum': '', 'rendered_fields': {}, 'error': ERRORS['ERR_FINANCIAL_MISMATCH']}
    rendered_fields = {
        'customer_name': application_data.get('customer_name'),
        'cif': application_data.get('cif'),
        'application_id': application_data.get('application_id'),
        'offer_id': application_data.get('offer_id'),
        'amount': principal,
        'tenure_months': tenure,
        'annual_rate_pct': annual_rate,
        'emi': offered_emi,
        'computed_emi': computed_emi
    }
    content = f"AGREEMENT\nTemplate:{template_id}\nCustomer:{rendered_fields['customer_name']}\nCIF:{rendered_fields['cif']}\nAmount:{principal}\nTenure:{tenure}\nRate:{annual_rate}\nEMI:{offered_emi}\nCOMPUTED_EMI:{computed_emi}\nTIMESTAMP:{_now_iso()}"
    document_bytes = content.encode('utf-8')
    checksum = hashlib.sha256(document_bytes).hexdigest()
    audit_log('TEMPLATE_POPULATED', application_data.get('application_id'), application_data.get('initiated_by'), {'template_id': template_id, 'checksum': checksum, 'rendered_fields': rendered_fields})
    return {'document': document_bytes, 'checksum': checksum, 'rendered_fields': rendered_fields}

def initiate_esign(document: bytes, signers: list, application_id: str, offer_id: str, idempotency_key: str) -> Dict[str, Any]:
    if not idempotency_key:
        return {'init_status': 'FAILED', 'provider_txn_id': '', 'error': ERRORS['ERR_ESIGN_INIT_FAIL']}
    existing = idempotency_store.get(idempotency_key)
    if existing:
        return {'init_status': existing.get('init_status', 'INITIATED'), 'provider_txn_id': existing.get('provider_txn_id', '')}
    def _call():
        txn_id = str(uuid.uuid4())
        e_sign_provider_store[txn_id] = {'application_id': application_id, 'offer_id': offer_id, 'signers': signers, 'document': document, 'status': 'INITIATED', 'created_at': _now_iso()}
        return {'init_status': 'INITIATED', 'provider_txn_id': txn_id}
    try:
        result = _retry_external(_call, idempotency_key=idempotency_key)
        audit_log('ESIGN_INITIATED', application_id, None, {'provider_txn_id': result['provider_txn_id'], 'idempotency_key': idempotency_key})
        return {'init_status': result['init_status'], 'provider_txn_id': result['provider_txn_id']}
    except ExternalRetriesExhausted:
        return {'init_status': 'FAILED', 'provider_txn_id': '', 'error': ERRORS['ERR_EXTERNAL_RETRY_EXHAUSTED']}
    except Exception:
        return {'init_status': 'FAILED', 'provider_txn_id': '', 'error': ERRORS['ERR_ESIGN_INIT_FAIL']}

def handle_esign_callback(callback_payload: dict) -> Dict[str, Any]:
    try:
        txn_id = callback_payload.get('provider_txn_id')
        signature_ok = callback_payload.get('signature_valid', False)
        if not txn_id or txn_id not in e_sign_provider_store:
            return {'processed': False, 'stored_document_ref': '', 'error': ERRORS['ERR_ESIGN_CALLBACK_INVALID']}
        record = e_sign_provider_store[txn_id]
        if not signature_ok:
            record['status'] = 'FAILED'
            audit_log('ESIGN_CALLBACK_INVALID', record.get('application_id'), None, {'provider_txn_id': txn_id})
            return {'processed': False, 'stored_document_ref': '', 'error': ERRORS['ERR_ESIGN_CALLBACK_INVALID']}
        signed_blob = callback_payload.get('signed_document')
        if not signed_blob:
            return {'processed': False, 'stored_document_ref': '', 'error': ERRORS['ERR_ESIGN_CALLBACK_INVALID']}
        try:
            store_resp = store_signed_document(record.get('application_id'), signed_blob, {'provider_txn_id': txn_id, 'type': 'e-sign'})
        except Exception:
            return {'processed': False, 'stored_document_ref': '', 'error': ERRORS['ERR_DOC_STORE_FAIL']}
        record['status'] = 'COMPLETED'
        record['signed_ref'] = store_resp.get('document_id')
        applications[record.get('application_id')]['document_status'] = 'Signed'
        audit_log('ESIGN_COMPLETED', record.get('application_id'), None, {'provider_txn_id': txn_id, 'signed_ref': store_resp.get('document_id')})
        notify_customer(record.get('application_id'), 'AgreementSigned', ['SMS', 'EMAIL'], {'document_ref': store_resp.get('document_id')})
        if config['mandate_required_for_disbursal']:
            mandate_ref = e_mandate_store.get(record.get('application_id'), {}).get('mandate_reference')
            if not mandate_ref:
                applications[record.get('application_id')]['mandate_status'] = 'Missing'
                return {'processed': True, 'stored_document_ref': store_resp.get('document_id'), 'warning': ERRORS['ERR_MANDATE_NOT_CONFIRMED']}
        push_resp = push_to_core_for_disbursal(record.get('application_id'), store_resp.get('document_id'), e_mandate_store.get(record.get('application_id'), {}).get('mandate_reference'))
        return {'processed': True, 'stored_document_ref': store_resp.get('document_id'), 'core_ref': push_resp.get('reference_id')}
    except Exception as e:
        logger.error('handle_esign_callback error %s', str(e))
        return {'processed': False, 'stored_document_ref': '', 'error': ERRORS['ERR_ESIGN_CALLBACK_INVALID']}

def initiate_physical_workflow(application_id: str, document: bytes, pickup_details: dict) -> Dict[str, Any]:
    try:
        task_id = str(uuid.uuid4())
        stored = store_signed_document(application_id, document, {'type': 'pre-sign', 'task_id': task_id})
        physical_tasks[task_id] = {'application_id': application_id, 'pickup_details': pickup_details, 'created_at': _now_iso(), 'status': 'AWAITING_PICKUP', 'pre_sign_ref': stored.get('document_id')}
        applications[application_id]['document_status'] = 'PendingPhysicalSignature'
        audit_log('PHYSICAL_WORKFLOW_INITIATED', application_id, pickup_details.get('initiated_by'), {'task_id': task_id})
        return {'task_id': task_id, 'message': 'Physical workflow initiated'}
    except Exception as e:
        logger.error('initiate_physical_workflow error %s', str(e))
        return {'task_id': '', 'message': ERRORS['ERR_DOC_STORE_FAIL']}

def confirm_scanned_signed_document(application_id: str, scanned_document: bytes, uploader_id: str) -> Dict[str, Any]:
    try:
        if b'SIGNED' not in scanned_document:
            return {'ok': False, 'stored_document_ref': '', 'error': 'Scanned document validation failed: signatures/pages missing'}
        stored = store_signed_document(application_id, scanned_document, {'uploader_id': uploader_id, 'type': 'scanned-signed'})
        applications[application_id]['document_status'] = 'Signed'
        audit_log('PHYSICAL_SIGNED_UPLOADED', application_id, uploader_id, {'stored_ref': stored.get('document_id')})
        notify_customer(application_id, 'AgreementSigned', ['SMS'], {'document_ref': stored.get('document_id')})
        push_resp = push_to_core_for_disbursal(application_id, stored.get('document_id'), e_mandate_store.get(application_id, {}).get('mandate_reference'))
        return {'ok': True, 'stored_document_ref': stored.get('document_id'), 'core_ref': push_resp.get('reference_id')}
    except Exception as e:
        logger.error('confirm_scanned_signed_document error %s', str(e))
        return {'ok': False, 'stored_document_ref': '', 'error': ERRORS['ERR_DOC_STORE_FAIL']}

def confirm_e_mandate(application_id: str, mandate_reference: str, provider_status: str) -> Dict[str, Any]:
    try:
        e_mandate_store[application_id] = {'mandate_reference': mandate_reference, 'status': provider_status, 'confirmed_at': _now_iso()}
        if config['mandate_required_for_disbursal'] and provider_status != 'ACTIVE':
            applications[application_id]['mandate_status'] = 'Failed'
            audit_log('MANDATE_CONFIRMATION_FAILED', application_id, None, {'mandate_reference': mandate_reference, 'status': provider_status})
            return {'ok': False, 'message': ERRORS['ERR_MANDATE_NOT_CONFIRMED']}
        applications[application_id]['mandate_status'] = 'Active'
        audit_log('MANDATE_CONFIRMED', application_id, None, {'mandate_reference': mandate_reference})
        return {'ok': True, 'message': 'Mandate confirmed'}
    except Exception as e:
        logger.error('confirm_e_mandate error %s', str(e))
        return {'ok': False, 'message': ERRORS['ERR_DOC_STORE_FAIL']}

def store_signed_document(application_id: str, document: bytes, metadata: dict) -> Dict[str, Any]:
    try:
        document_id = str(uuid.uuid4())
        encrypted = fernet.encrypt(document)
        storage_path = f'secure://documents/{document_id}'
        entry = {'document_id': document_id, 'application_id': application_id, 'encrypted_blob': encrypted, 'metadata': metadata, 'stored_at': _now_iso(), 'storage_path': storage_path}
        with lock:
            document_repository[document_id] = entry
        audit_log('DOCUMENT_STORED', application_id, metadata.get('uploader_id'), {'document_id': document_id, 'storage_path': storage_path})
        return {'document_id': document_id, 'storage_path': storage_path}
    except Exception as e:
        logger.error('store_signed_document error %s', str(e))
        raise

def notify_customer(application_id: str, event_type: str, channels: list, message_payload: dict) -> Dict[str, Any]:
    try:
        notif_id = str(uuid.uuid4())
        entry = {'notification_id': notif_id, 'application_id': application_id, 'event_type': event_type, 'channels': channels, 'payload': message_payload, 'sent_at': _now_iso()}
        with lock:
            notifications.append(entry)
        audit_log('NOTIFICATION_SENT', application_id, None, {'notification_id': notif_id, 'event_type': event_type})
        return {'sent': True, 'details': {'notification_id': notif_id}}
    except Exception as e:
        logger.error('notify_customer error %s', str(e))
        return {'sent': False, 'details': {}}

def push_to_core_for_disbursal(application_id: str, signed_document_ref: str, mandate_ref: Optional[str]) -> Dict[str, Any]:
    try:
        reference_id = str(uuid.uuid4())
        payload = {'application_id': application_id, 'signed_document_ref': signed_document_ref, 'mandate_ref': mandate_ref, 'timestamp': _now_iso()}
        core_integration_store.append({'reference_id': reference_id, 'payload': payload})
        audit_log('PUSHED_TO_CORE', application_id, None, {'reference_id': reference_id})
        return {'pushed': True, 'reference_id': reference_id}
    except Exception as e:
        logger.error('push_to_core_for_disbursal error %s', str(e))
        return {'pushed': False, 'reference_id': ''}

def get_agreement_status(application_id: str) -> Dict[str, Any]:
    app = applications.get(application_id)
    if not app:
        return {'status': 'NotFound', 'details': {}}
    details = {
        'application_id': application_id,
        'status': app.get('document_status'),
        'mandate_status': app.get('mandate_status'),
        'last_updated': app.get('last_updated'),
        'provider_txn_ids': []
    }
    for txn_id, rec in e_sign_provider_store.items():
        if rec.get('application_id') == application_id:
            details['provider_txn_ids'].append({'txn_id': txn_id, 'status': rec.get('status'), 'signed_ref': rec.get('signed_ref')})
    doc_refs = [d for d,v in document_repository.items() if v.get('application_id') == application_id]
    details['stored_documents'] = doc_refs
    return {'status': 'OK', 'details': details}

def generate_agreement(application_id: str, offer_id: str, initiated_by: str, channel: str) -> Dict[str, Any]:
    try:
        if not _validate_mutation_role(initiated_by):
            return {'status': 'FAILED', 'task_id': '', 'message': ERRORS['ERR_UNAUTHORIZED']}
        pre = validate_preconditions(application_id)
        if not pre.get('ok'):
            return {'status': 'FAILED', 'task_id': '', 'message': pre.get('errors')}
        app = applications.get(application_id)
        offer = offers.get(offer_id)
        product_variant = app.get('product_variant')
        customer_segment = app.get('customer_segment')
        region = app.get('region')
        sel = select_template(product_variant, customer_segment, region, offer)
        if sel.get('error'):
            return {'status': 'FAILED', 'task_id': '', 'message': sel.get('error')}
        template_id = sel.get('template_id')
        populated = populate_template(template_id, app, offer)
        if populated.get('error'):
            return {'status': 'FAILED', 'task_id': '', 'message': populated.get('error')}
        task_id = str(uuid.uuid4())
        applications[application_id]['last_updated'] = _now_iso()
        audit_log('AGREEMENT_GENERATION_INITIATED', application_id, initiated_by, {'task_id': task_id, 'template_id': template_id, 'channel': channel})
        if channel == 'digital' and app.get('esign_legal_allowed') and consents_store.get(application_id, {}).get('esign'):
            signers = [{'name': app.get('customer_name'), 'role': 'APPLICANT'}]
            idempotency_key = str(uuid.uuid4())
            esign_resp = initiate_esign(populated.get('document'), signers, application_id, offer_id, idempotency_key)
            if esign_resp.get('init_status') != 'INITIATED':
                return {'status': 'FAILED', 'task_id': task_id, 'message': esign_resp.get('error', ERRORS['ERR_ESIGN_INIT_FAIL'])}
            applications[application_id]['esign_txn_id'] = esign_resp.get('provider_txn_id')
            audit_log('ESIGN_FLOW_STARTED', application_id, initiated_by, {'provider_txn_id': esign_resp.get('provider_txn_id'), 'task_id': task_id})
            return {'status': 'INITIATED', 'task_id': task_id, 'message': 'E-sign initiated'}
        else:
            pickup_details = {'initiated_by': initiated_by, 'branch': app.get('region'), 'sla_days': 5}
            phys = initiate_physical_workflow(application_id, populated.get('document'), pickup_details)
            return {'status': 'INITIATED', 'task_id': phys.get('task_id'), 'message': phys.get('message')}
    except Exception as e:
        logger.error('generate_agreement error %s', str(e))
        return {'status': 'FAILED', 'task_id': '', 'message': 'Internal error'}

def _initialize_mock_data():
    users['op_user'] = {'user_id': 'op_user', 'role': 'OperationsUser'}
    users['rm_user'] = {'user_id': 'rm_user', 'role': 'SalesUser'}
    applications['app-123'] = {'application_id': 'app-123', 'status': 'Approved', 'offer_id': 'offer-123', 'product_variant': 'LOAN_BASIC', 'customer_segment': 'Salaried', 'region': 'GLOBAL', 'customer_name': 'John Doe', 'cif': 'CIF123', 'initiated_by': 'op_user', 'document_status': 'NotStarted', 'last_updated': _now_iso(), 'esign_legal_allowed': True}
    offers['offer-123'] = {'offer_id': 'offer-123', 'amount': 100000.0, 'tenure_months': 24, 'annual_rate_pct': 12.0, 'emi': _compute_emi(100000.0, 12.0, 24)}
    kyc_checklists['app-123'] = {'required_documents': ['ID_PROOF', 'ADDRESS_PROOF'], 'documents': {'ID_PROOF': {'expiry': (datetime.utcnow() + timedelta(days=365)).isoformat()}, 'ADDRESS_PROOF': {'expiry': (datetime.utcnow() + timedelta(days=365)).isoformat()}}}
    consents_store['app-123'] = {'bureau': True, 'data_usage': True, 'esign': True}
    policy_store['app-123'] = {'negative_list': False, 'blacklisted_profession': False, 'pincode_restricted': False, 'internal_exposure': False}
    templates_store['LOAN_BASIC:Salaried'] = [{'template_id': 'tpl-001', 'version': 'v2', 'region': 'GLOBAL', 'status': 'Approved'}]

_initialize_mock_data()
