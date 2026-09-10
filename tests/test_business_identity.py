from ioc_rejudge.business_identity import trusted_business_identity
from ioc_rejudge.adjudicator import adjudicate
from ioc_rejudge.config import Config
from ioc_rejudge.evidence import extract_evidence
from ioc_rejudge.models import IocDossier
from ioc_rejudge.normalize import merge_records
from tests.fixtures import build_record


def _dossier(ioc="example.com", ioc_type="domain", **fields):
    dossier = IocDossier(ioc=ioc, ioc_type=ioc_type, **fields)
    return dossier


def test_default_icp_registration_and_same_site_official_website():
    dossier = _dossier(
        icp_website="京ICP备123456号",
        official_website="https://example.com/about",
    )

    assert trusted_business_identity(dossier, ["icp_website", "official_website"])


def test_icp_url_and_same_site_official_website_anchor_identity():
    dossier = _dossier(
        icp_website="https://example.com/备案",
        official_website="https://www.example.com",
    )

    assert trusted_business_identity(dossier, ["icp_website", "official_website"])


def test_host_matching_normalizes_case_trailing_dot_and_one_www_prefix():
    dossier = _dossier(
        ioc="Example.COM.",
        icp_website="ICP-备案号",
        official_website="HTTPS://WWW.EXAMPLE.COM./home",
    )

    assert trusted_business_identity(dossier, ["icp_website", "official_website"])


def test_domain_port_and_scheme_less_url_targets_are_supported():
    domain_port = _dossier(
        ioc="example.com:8443",
        ioc_type="domain_port",
        official_website="example.com:443",
    )
    normalized_url = _dossier(
        ioc="example.com/path",
        ioc_type="url",
        official_website="https://example.com",
    )

    assert trusted_business_identity(domain_port, ["official_website"])
    assert trusted_business_identity(normalized_url, ["official_website"])


def test_unrelated_official_website_does_not_anchor_identity():
    dossier = _dossier(
        icp_website="ICP-备案号",
        official_website="https://other.example",
    )

    assert not trusted_business_identity(dossier, ["icp_website", "official_website"])


def test_unrelated_icp_url_is_rejected_even_with_matching_official_website():
    dossier = _dossier(
        icp_website="https://other.example",
        official_website="https://example.com",
    )

    assert not trusted_business_identity(dossier, ["icp_website", "official_website"])


def test_subdomain_cannot_impersonate_target_host():
    dossier = _dossier(official_website="https://login.example.com")

    assert not trusted_business_identity(dossier, ["official_website"])


def test_website_userinfo_and_illegal_port_are_rejected():
    userinfo = _dossier(official_website="https://user:pass@example.com")
    illegal_port = _dossier(official_website="https://example.com:65536")
    non_http = _dossier(official_website="ftp://example.com")

    assert not trusted_business_identity(userinfo, ["official_website"])
    assert not trusted_business_identity(illegal_port, ["official_website"])
    assert not trusted_business_identity(non_http, ["official_website"])


def test_page_title_alone_cannot_provide_identity_anchor():
    dossier = _dossier(page_title="Example business")

    assert not trusted_business_identity(dossier, ["page_title"])


def test_custom_icp_and_page_title_fields_can_anchor_with_icp_url():
    dossier = _dossier(
        icp_website="https://example.com",
        page_title="Example business",
        official_website="",
    )

    assert trusted_business_identity(dossier, ["icp_website", "page_title"])


def test_plain_icp_text_and_page_title_are_only_auxiliary():
    dossier = _dossier(
        icp_website="京ICP备123456号",
        page_title="Example business",
    )

    assert not trusted_business_identity(dossier, ["icp_website", "page_title"])


def test_selected_fields_must_all_be_non_empty():
    dossier = _dossier(official_website="https://example.com", page_title="")

    assert not trusted_business_identity(dossier, ["official_website", "page_title"])
    assert not trusted_business_identity(dossier, [])


def test_current_icp_conflict_blocks_identity():
    dossier = _dossier(
        icp_website="京ICP备123456号",
        official_website="https://example.com",
    )
    dossier.current_icp_conflict = True

    assert not trusted_business_identity(dossier, ["icp_website", "official_website"])


def test_ip_targets_do_not_establish_business_domain_identity():
    dossier = _dossier(
        ioc="192.0.2.10",
        ioc_type="ip",
        official_website="https://192.0.2.10",
    )

    assert not trusted_business_identity(dossier, ["official_website"])


def test_ip_url_cannot_establish_business_domain_identity():
    dossier = _dossier(
        ioc="192.0.2.10/path", ioc_type="url",
        official_website="https://192.0.2.10",
    )
    assert not trusted_business_identity(dossier, ["official_website"])


def test_unrelated_websites_cannot_clear_operator_malice_through_either_path():
    dossier = extract_evidence(merge_records([build_record(
        "changed.invalid",
        source=["manual"],
        context="changed.invalid trojan malware",
        icp_website="https://unrelated.invalid",
        official_website="https://another.invalid",
        whois={"expiresDate": "2020-01-01"},
        ownership_change={"previous": "old owner", "current": "new owner"},
    )]), Config())

    assert not any("trusted_business" in item.tags for item in dossier.evidence_e)
    assert not dossier.profile.domain.get("has_trusted_business_identity", False)
    assert adjudicate(dossier, Config()).disposition == "review"


def test_profile_cannot_bypass_configured_business_fields():
    config = Config()
    config.rules.trusted_business_fields = ["page_title"]
    dossier = extract_evidence(merge_records([build_record(
        "configured.invalid", icp_website="ICP-CURRENT",
        official_website="https://configured.invalid", page_title="Business site",
    )]), config)

    assert not any("trusted_business" in item.tags for item in dossier.evidence_e)
