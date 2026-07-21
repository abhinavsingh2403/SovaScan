from sovascan.core.severity_scorer import Severity, SeverityScorer


class MockFinding:
    def __init__(self, id, title, description, category, file_path, line_number, evidence, remediation, severity="medium", cvss_score=0.0):
        self.id = id
        self.title = title
        self.description = description
        self.category = category
        self.file_path = file_path
        self.line_number = line_number
        self.evidence = evidence
        self.remediation = remediation
        self.severity = severity
        self.cvss_score = cvss_score
        self.metadata = {}


def test_severity_scorer_banking_path_criticality():
    scorer = SeverityScorer(banking_context=True)

    # 1. Base finding (medium = 5.0 base score)
    f_base = MockFinding("1", "Weak Crypto", "Desc", "crypto", "src/utils/helpers.py", 10, "md5", "remedy")
    res_base = scorer.score(f_base)
    assert res_base.base_score == 5.0
    assert res_base.final_score == 5.0
    assert res_base.severity == Severity.MEDIUM

    # 2. Finding in payment directory (+2.0 critical_banking_module, +1.5 banking_context modifiers -> 8.5 score -> HIGH severity)
    f_payment = MockFinding("2", "Weak Crypto", "Desc", "crypto", "src/payments/processor.py", 10, "md5", "remedy")
    res_payment = scorer.score(f_payment)
    assert res_payment.base_score == 5.0
    assert any(name == "critical_banking_module" for name, _ in res_payment.contextual_modifiers)
    assert any(name == "banking_context" for name, _ in res_payment.contextual_modifiers)
    assert res_payment.final_score == 8.5
    assert res_payment.severity == Severity.HIGH

    # 3. Finding in auth directory (+2.0 critical_banking_module modifier, no banking context keyword -> 7.0 score -> HIGH severity)
    f_auth = MockFinding("3", "Weak Crypto", "Desc", "crypto", "src/auth/login.py", 10, "md5", "remedy")
    res_auth = scorer.score(f_auth)
    assert any(name == "critical_banking_module" for name, _ in res_auth.contextual_modifiers)
    assert res_auth.final_score == 7.0
    assert res_auth.severity == Severity.HIGH


def test_severity_scorer_test_directory_reduction():
    scorer = SeverityScorer(banking_context=False)

    # Finding in test directory should get -1.0 modifier (avoiding critical directories to isolate check)
    f_test = MockFinding("4", "Weak Crypto", "Desc", "crypto", "/tests/utils/test_helpers.py", 10, "md5", "remedy")
    res_test = scorer.score(f_test)
    assert any(name == "test_directory" for name, _ in res_test.contextual_modifiers)
    # 5.0 - 1.0 = 4.0 (Medium)
    assert res_test.final_score == 4.0
