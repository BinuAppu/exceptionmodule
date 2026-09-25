"""SAML 2.0 service-provider integration.

PySAML2 is imported lazily so the rest of the application can run in
bootstrap mode before the optional native xmlsec runtime is installed.  SAML
authentication itself fails closed when the maintained toolkit or xmlsec is
not available; metadata and configuration validation remain available.
"""

from __future__ import annotations

import base64
import binascii
import html
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session as DbSession

from app.core.errors import AuthenticationError, DomainError
from app.core.security import generate_opaque_token
from app.services.sso import (
    _CONTROL_RE,
    MAX_SAML_RESPONSE_BYTES,
    SAML_BINDING_HTTP_POST,
    SAML_BINDING_HTTP_REDIRECT,
    EffectiveSSOConfig,
    TransactionSecret,
    claim_transaction,
    get_signing_private_key,
    invalidate_transaction,
    verify_browser_binding,
)

try:  # Optional at import time; required for actual SAML login.
    from saml2 import BINDING_HTTP_POST as PY_SAML_POST
    from saml2 import BINDING_HTTP_REDIRECT as PY_SAML_REDIRECT
    from saml2.client import Saml2Client
    from saml2.config import config_factory
    from saml2.saml import NAMEID_FORMAT_PERSISTENT

    PYSAML2_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised in minimal local installs
    PY_SAML_POST = SAML_BINDING_HTTP_POST
    PY_SAML_REDIRECT = SAML_BINDING_HTTP_REDIRECT
    Saml2Client = None  # type: ignore[assignment,misc]
    config_factory = None  # type: ignore[assignment]
    NAMEID_FORMAT_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    PYSAML2_AVAILABLE = False

try:
    from defusedxml.lxml import etree as secure_etree
except ImportError:  # pragma: no cover
    from defusedxml import ElementTree as secure_etree


class _SamlRawMessageFilter(logging.Filter):
    """Keep PySAML2's debug diagnostics from serializing raw assertions."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not record.name.startswith("saml2"):
            return True
        try:
            rendered = str(record.msg) + " " + " ".join(str(item) for item in record.args)
        except Exception:
            return False
        lowered = rendered.casefold()
        return not any(marker in lowered for marker in ("<saml", "<?xml", "samlresponse", "xmlstr:"))


logging.getLogger("saml2").addFilter(_SamlRawMessageFilter())
logging.getLogger("saml2").setLevel(logging.WARNING)


@dataclass(frozen=True)
class SAMLIdentity:
    subject: str
    email: str
    display_name: str
    authn_context: str | None = None
    amr: tuple[str, ...] = ()


@dataclass(frozen=True)
class SAMLRequest:
    url: str | None
    relay_state: str
    request_id: str
    transaction: TransactionSecret
    form: str | None = None


def _pem(value: str) -> str:
    value = value.strip()
    if "BEGIN CERTIFICATE" in value:
        return value
    return "-----BEGIN CERTIFICATE-----\n" + value + "\n-----END CERTIFICATE-----"


def _idp_metadata_xml(config: EffectiveSSOConfig) -> str:
    certificate = _pem(config.idp_x509_certificate or "")
    certificate = certificate.replace("-----BEGIN CERTIFICATE-----", "").replace(
        "-----END CERTIFICATE-----", ""
    ).strip()
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{html.escape(config.idp_entity_id or '', quote=True)}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>{html.escape(certificate, quote=False)}</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="{SAML_BINDING_HTTP_REDIRECT}" Location="{html.escape(config.sso_url or '', quote=True)}" />
  </IDPSSODescriptor>
</EntityDescriptor>"""


def sp_metadata(config: EffectiveSSOConfig) -> bytes:
    """Return stable SP metadata without ever including the private key."""

    if not config.sp_entity_id or not config.acs_url:
        raise DomainError("SAML SP entity ID and ACS URL are required", code="saml_not_configured")
    certificate = config.db_config.sp_x509_certificate if config.db_config else None
    if not certificate:
        raise DomainError("SAML SP signing certificate is not configured", code="saml_not_configured")
    cert_body = certificate.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").strip()
    metadata = f"""<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{html.escape(config.sp_entity_id, quote=True)}">
  <SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>{html.escape(cert_body, quote=False)}</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <AssertionConsumerService Binding="{SAML_BINDING_HTTP_POST}" Location="{html.escape(config.acs_url, quote=True)}" index="0" isDefault="true" />
  </SPSSODescriptor>
</EntityDescriptor>"""
    return metadata.encode("utf-8")


def _temporary_pem(directory: str, name: str, value: str, mode: int = 0o600) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="ascii") as handle:
        handle.write(value if value.endswith("\n") else value + "\n")
    os.chmod(path, mode)
    return path


def _saml_client(config: EffectiveSSOConfig, private_key: str, certificate: str, directory: str):
    if not PYSAML2_AVAILABLE or config_factory is None or Saml2Client is None:
        raise DomainError("SAML runtime is not installed", code="saml_runtime_unavailable", status_code=503)
    if not shutil.which("xmlsec1"):
        raise DomainError("SAML xmlsec runtime is unavailable", code="saml_runtime_unavailable", status_code=503)
    key_path = _temporary_pem(directory, "sp-key.pem", private_key)
    cert_path = _temporary_pem(directory, "sp-cert.pem", _pem(certificate), 0o644)
    idp_metadata_path = os.path.join(directory, "idp-metadata.xml")
    with open(idp_metadata_path, "w", encoding="utf-8") as handle:
        handle.write(_idp_metadata_xml(config))
    settings = {
        "entityid": config.sp_entity_id,
        "description": "Exception Manager SAML service provider",
        "key_file": key_path,
        "cert_file": cert_path,
        "accepted_time_diff": 60,
        "verify_ssl_cert": True,
        "only_use_keys_in_metadata": True,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(config.acs_url, PY_SAML_POST)],
                    "single_logout_service": [],
                },
                "authn_requests_signed": True,
                "want_response_signed": True,
                "want_assertions_signed": True,
                "want_assertions_or_response_signed": True,
                "allow_unsolicited": False,
                "allow_unknown_attributes": False,
                "name_id_policy_format": NAMEID_FORMAT_PERSISTENT,
            }
        },
        "metadata": {"local": [idp_metadata_path]},
        "organization": {
            "name": "Exception Manager",
            "display_name": [("Exception Manager", "en")],
            "url": config.acs_url,
        },
    }
    try:
        saml_config = config_factory("sp", settings)
        return Saml2Client(config=saml_config)
    except Exception as exc:
        raise DomainError("SAML configuration could not be loaded", code="invalid_saml_configuration") from exc


def _location_from_binding(info: dict[str, Any]) -> str | None:
    for key, value in info.get("headers", []):
        if str(key).lower() == "location":
            return str(value)
    return None


def _post_form(info: dict[str, Any]) -> str:
    data = info.get("data", "")
    if isinstance(data, (list, tuple)):
        data = data[0] if data else ""
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="strict")
    # PySAML2's POST binding returns a complete form.  Do not log or persist
    # the request body; it contains only the signed AuthnRequest and opaque
    # RelayState and is returned directly to the browser.
    return str(data)


def begin_saml_login(
    db: DbSession, request, config: EffectiveSSOConfig
) -> tuple[Any, SAMLRequest]:
    """Start an SP-initiated SAML flow using a one-time RelayState."""

    if not config.enabled or config.provider != "saml":
        raise AuthenticationError("SAML SSO is not configured")
    settings = request.app.state.settings
    private_key = get_signing_private_key(db, config, settings)
    if not private_key:
        raise AuthenticationError("SAML signing key is not configured")
    certificate = config.db_config.sp_x509_certificate if config.db_config else None
    if not certificate:
        raise AuthenticationError("SAML signing certificate is not configured")
    relay_state = generate_opaque_token(32)
    browser_binding = generate_opaque_token(32)
    with tempfile.TemporaryDirectory(prefix="em-saml-") as directory:
        client = _saml_client(config, private_key, certificate, directory)
        try:
            request_id, authn_request = client.create_authn_request(
                config.sso_url,
                binding=PY_SAML_POST,
                sign=True,
                nameid_format=NAMEID_FORMAT_PERSISTENT,
                assertion_consumer_service_url=config.acs_url,
            )
            info = client.apply_binding(
                PY_SAML_REDIRECT,
                str(authn_request),
                config.sso_url,
                relay_state=relay_state,
                sign=True,
            )
        except Exception as exc:
            raise AuthenticationError("SAML login could not be started") from exc
    # The request ID is persisted only as a hash; the encrypted envelope keeps
    # the exact value needed to correlate the response.
    from app.services.sso import create_transaction

    secret = create_transaction(
        db,
        request,
        config,
        "saml",
        protocol_payload={"request_id": request_id, "acs_url": config.acs_url, "idp_entity_id": config.idp_entity_id},
        return_path=request.query_params.get("return_to", "/"),
        relay_state=relay_state,
        browser_binding=browser_binding,
        request_id=str(request_id),
    )
    return client, SAMLRequest(
        url=_location_from_binding(info),
        relay_state=relay_state,
        request_id=str(request_id),
        transaction=secret,
        form=_post_form(info) if _location_from_binding(info) is None else None,
    )


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except (TypeError, ValueError, OverflowError):
        return None


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _first(element, name: str):
    for child in element.iter():
        if _local_name(child.tag) == name:
            return child
    return None


def _text(element, name: str) -> str | None:
    found = _first(element, name)
    return (found.text or "").strip() if found is not None else None


def _attribute(element, name: str) -> str | None:
    value = element.get(name)
    return value.strip() if isinstance(value, str) else None


def validate_saml_response_xml(
    xml_text: str,
    config: EffectiveSSOConfig,
    request_id: str,
    *,
    now: datetime | None = None,
) -> None:
    """Perform explicit protocol checks before handing XML to PySAML2.

    The raw response is never logged or persisted.  PySAML2 subsequently
    verifies XML signatures and certificate metadata; these checks cover
    destination, audience, issuer, recipient, request correlation, and time
    windows explicitly so a library default cannot weaken them.
    """

    if not xml_text or len(xml_text.encode("utf-8")) > MAX_SAML_RESPONSE_BYTES:
        raise AuthenticationError("SAML response is invalid")
    parser = (  # noqa: S314 - defusedxml/lxml parser has entity/network limits
        secure_etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
        if secure_etree.__name__.endswith("lxml.etree")
        else None
    )
    try:
        root = (  # noqa: S314 - input is size-bounded and parsed with the hardened parser
            secure_etree.fromstring(xml_text.encode("utf-8"), parser)
            if parser is not None
            else secure_etree.fromstring(xml_text.encode("utf-8"))
        )
    except Exception as exc:
        raise AuthenticationError("SAML response is invalid") from exc
    if _local_name(root.tag) not in {"Response", "AuthnResponse"}:
        raise AuthenticationError("SAML response is invalid")
    destination = _attribute(root, "Destination")
    if _CONTROL_RE.search(str(destination or "")) or destination != config.acs_url:
        raise AuthenticationError("SAML response destination is invalid")
    if _attribute(root, "InResponseTo") != request_id:
        raise AuthenticationError("SAML response request correlation is invalid")
    status_codes = [str(item.get("Value", "")).split(":")[-1] for item in root.iter() if _local_name(item.tag) == "StatusCode"]
    if status_codes and status_codes[0] != "Success":
        raise AuthenticationError("SAML authentication was rejected")
    signatures = []
    for item in root.iter():
        if _local_name(item.tag) != "Signature":
            continue
        get_parent = getattr(item, "getparent", None)
        parent = get_parent() if callable(get_parent) else None
        while parent is not None:
            if _local_name(parent.tag) in {"Response", "AuthnResponse", "Assertion"}:
                signatures.append(item)
                break
            get_parent = getattr(parent, "getparent", None)
            parent = get_parent() if callable(get_parent) else None
    if not signatures and secure_etree.__name__.endswith("lxml.etree"):
        raise AuthenticationError("SAML response is unsigned")
    if not signatures:
        # The stdlib fallback has no parent pointers; only accept signatures
        # that are direct children of the response or assertion elements.
        signatures = [
            item
            for item in root.iter()
            if _local_name(item.tag) == "Signature"
            and any(_local_name(parent.tag) in {"Response", "AuthnResponse", "Assertion"} for parent in root.iter() if item in list(parent))
        ]
        if not signatures:
            raise AuthenticationError("SAML response is unsigned")
    issuer_values = [str(item.text or "").strip() for item in root.iter() if _local_name(item.tag) == "Issuer"]
    if not issuer_values or any(value != config.idp_entity_id for value in issuer_values):
        raise AuthenticationError("SAML response issuer is invalid")
    assertion = next((item for item in root.iter() if _local_name(item.tag) == "Assertion"), None)
    if assertion is None:
        raise AuthenticationError("SAML response assertion is missing")
    now = now or datetime.now(UTC)
    audience_values = {str(item.text or "").strip() for item in assertion.iter() if _local_name(item.tag) == "Audience"}
    if config.sp_entity_id not in audience_values:
        raise AuthenticationError("SAML response audience is invalid")
    conditions = next((item for item in assertion.iter() if _local_name(item.tag) == "Conditions"), None)
    if conditions is None:
        raise AuthenticationError("SAML response conditions are missing")
    not_before = _parse_timestamp(conditions.get("NotBefore"))
    not_after = _parse_timestamp(conditions.get("NotAfter"))
    if (not_before and now + timedelta(seconds=60) < not_before) or (
        not_after and now - timedelta(seconds=60) >= not_after
    ):
        raise AuthenticationError("SAML response is expired or not yet valid")
    confirmations = [
        item for item in assertion.iter() if _local_name(item.tag) == "SubjectConfirmationData"
    ]
    if not confirmations:
        raise AuthenticationError("SAML response recipient is missing")
    for confirmation in confirmations:
        recipient = confirmation.get("Recipient")
        in_response_to = confirmation.get("InResponseTo")
        expiry = _parse_timestamp(confirmation.get("NotOnOrAfter"))
        if (
            recipient != config.acs_url
            or in_response_to != request_id
            or expiry is None
            or now - timedelta(seconds=60) >= expiry
        ):
            raise AuthenticationError("SAML response recipient or expiry is invalid")


def _attribute_values(response: Any, names: tuple[str, ...]) -> list[str]:
    ava = getattr(response, "ava", {}) or {}
    result: list[str] = []
    for key, values in ava.items():
        key_text = str(key).casefold()
        if key_text in {name.casefold() for name in names}:
            if isinstance(values, (list, tuple)):
                result.extend(str(value) for value in values)
            else:
                result.append(str(values))
    return result


def complete_saml_login(
    db: DbSession,
    request,
    response,
    encoded_response: str,
    relay_state: str | None,
) -> dict[str, Any]:
    """Validate a SAML POST response, then return the common session payload."""

    from app.services.sso import get_enabled_login_config, provision_sso_user

    config = get_enabled_login_config(db, request.app.state.settings)
    if not relay_state or len(relay_state) > 1024:
        raise AuthenticationError("SAML response is invalid")
    transaction, envelope, _ = claim_transaction(
        db,
        lookup_field="relay_state_hash",
        raw_value=relay_state,
        config=config,
        transaction_type="saml",
        settings=request.app.state.settings,
    )
    if not verify_browser_binding(request, transaction):
        invalidate_transaction(db, transaction.id, "browser_binding")
        raise AuthenticationError("SAML response is invalid")
    try:
        compact_response = "".join(str(encoded_response).split())
        compact_response += "=" * (-len(compact_response) % 4)
        raw = base64.b64decode(compact_response, validate=True)
    except (ValueError, binascii.Error):
        invalidate_transaction(db, transaction.id, "invalid_encoding")
        raise AuthenticationError("SAML response is invalid") from None
    if len(raw) > MAX_SAML_RESPONSE_BYTES or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        invalidate_transaction(db, transaction.id, "invalid_xml")
        raise AuthenticationError("SAML response is invalid")
    try:
        xml_text = raw.decode("utf-8")
        request_id = str(envelope.get("request_id") or "")
        if not request_id:
            raise ValueError
        validate_saml_response_xml(xml_text, config, request_id)
        private_key = get_signing_private_key(db, config, request.app.state.settings)
        certificate = config.db_config.sp_x509_certificate if config.db_config else None
        if not private_key or not certificate:
            raise ValueError
        with tempfile.TemporaryDirectory(prefix="em-saml-validate-") as directory:
            client = _saml_client(config, private_key, certificate, directory)
            authn_response = client.parse_authn_request_response(
                xml_text,
                PY_SAML_POST,
                outstanding={request_id: {}},
                outstanding_certs={request_id: {"cert": _pem(certificate), "key": private_key}},
                conv_info={"remote_addr": request.client.host if request.client else "", "request_uri": config.acs_url, "entity_id": config.sp_entity_id},
            )
        if authn_response is None:
            raise ValueError
        issuer = authn_response.issuer() if callable(getattr(authn_response, "issuer", None)) else str(getattr(authn_response, "issuer", ""))
        if issuer != config.idp_entity_id:
            raise ValueError
        name_id = getattr(authn_response, "name_id", None)
        subject = str(getattr(name_id, "text", name_id) or "").strip()
        email_values = _attribute_values(authn_response, (config.email_attribute, config.email_attribute.rsplit(":", 1)[-1], "email", "mail"))
        name_values = _attribute_values(authn_response, (config.name_attribute, config.name_attribute.rsplit(":", 1)[-1], "name", "displayName"))
        email = next((str(value).strip().casefold() for value in email_values if "@" in str(value)), "")
        display_name = next((str(value).strip() for value in name_values if str(value).strip()), email)
        if (
            not subject
            or len(subject) > 512
            or not email
            or len(email) > 320
            or _CONTROL_RE.search(subject)
            or _CONTROL_RE.search(email)
            or _CONTROL_RE.search(display_name)
        ):
            raise ValueError
        if config.allowed_domains and not any(email.endswith("@" + domain.casefold()) for domain in config.allowed_domains):
            raise ValueError
        user = provision_sso_user(db, config, subject, email, display_name)
    except AuthenticationError:
        raise
    except Exception as exc:
        invalidate_transaction(db, transaction.id, "saml_validation_failed")
        raise AuthenticationError("SAML response is invalid") from exc
    authn_info = []
    try:
        authn_info = authn_response.authn_info()
    except (AttributeError, TypeError, ValueError):
        authn_info = []
    authn_class = str(authn_info[0][0]) if authn_info else None
    authn_instant = authn_info[0][2] if authn_info else None
    return {
        "user": user,
        "provider": "saml",
        "auth_time": _parse_timestamp(authn_instant),
        "assurance_level": authn_class,
        "auth_methods": ["saml"],
        "return_path": transaction.return_path or "/",
    }


__all__ = [
    "PYSAML2_AVAILABLE",
    "SAMLIdentity",
    "SAMLRequest",
    "begin_saml_login",
    "complete_saml_login",
    "sp_metadata",
    "validate_saml_response_xml",
]
