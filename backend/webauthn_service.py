
import json
import os

from webauthn import (
    generate_registration_options,
    generate_authentication_options,
    verify_registration_response,
    verify_authentication_response,
)
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)

from storage import encode, decode

RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
RP_NAME = os.getenv(
    "WEBAUTHN_RP_NAME",
    "Zero Trust Identity Mesh"
)
ORIGIN = os.getenv(
    "WEBAUTHN_ORIGIN",
    "http://localhost:8000"
)


def create_registration_options(username, user_handle, credentials):
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=decode(user_handle),
        user_name=username,
        user_display_name=username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(
                id=decode(item["credential_id"])
            )
            for item in credentials
        ],
    )

    return options, json.loads(options_to_json(options))


def verify_registration(credential, expected_challenge):
    return verify_registration_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        require_user_verification=True,
    )


def create_login_options(credentials):
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=decode(item["credential_id"])
            )
            for item in credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    return options, json.loads(options_to_json(options))


def verify_login(credential, expected_challenge, stored_credential):
    return verify_authentication_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        credential_public_key=decode(
            stored_credential["public_key"]
        ),
        credential_current_sign_count=stored_credential["sign_count"],
        require_user_verification=True,
    )
