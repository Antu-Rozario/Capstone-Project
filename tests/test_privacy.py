import pytest

from ueba.privacy import lint_fields


@pytest.mark.parametrize(
    "text",
    [
        "U0042 is clearly malicious.",
        "This looks like data theft.",
        "The user was stealing customer lists.",
        "U0042 is an insider threat.",
        "A disgruntled employee exfiltrated files.",
        "The suspect accessed payroll.",
        "Possible FRAUD in Finance.",
        "They may be in financial difficulty.",
    ],
)
def test_accusatory_or_speculative_wording_is_rejected(text: str) -> None:
    violations = lint_fields({"summary": text})
    assert violations and violations[0].field == "summary"
    assert violations[0].kind == "accusatory_or_speculative"


@pytest.mark.parametrize(
    "text",
    [
        "U0042's file transfers deviated from their baseline and warrant review.",
        "Activity occurred outside usual hours on 4 nights.",
        "Possible legitimate explanations include a quarter-end deadline.",
        "This follows the Insider Risk Handling Policy.",
        "Transfers from a device not seen in the baseline.",
    ],
)
def test_neutral_activity_language_passes(text: str) -> None:
    assert lint_fields({"summary": text}) == []


def test_real_names_and_emails_are_rejected() -> None:
    v = lint_fields({"summary": "Files copied by Jane Q Doe."}, real_names=["Jane Q Doe"])
    assert [x.kind for x in v] == ["real_name"]
    v = lint_fields({"note": "Contact jane.doe@example.com"})
    assert [x.kind for x in v] == ["email_address"]


def test_every_field_and_list_item_is_checked() -> None:
    v = lint_fields({"summary": "fine", "possible_benign_explanations": ["ok", "a criminal act"]})
    assert len(v) == 1 and v[0].field == "possible_benign_explanations[1]"
