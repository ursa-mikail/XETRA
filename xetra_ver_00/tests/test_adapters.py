"""Verify every live adapter fails loudly and clearly without credentials
(never silently no-ops, never falls back to fabricated results)."""
import pytest

from xetra.adapters.bas.attackiq import AttackIQAdapter
from xetra.adapters.bas.pentera import PenteraAdapter
from xetra.adapters.bas.safebreach import SafeBreachAdapter
from xetra.adapters.bas.cymulate import CymulateAdapter
from xetra.adapters.siem.splunk import SplunkAdapter
from xetra.adapters.siem.sentinel import SentinelAdapter
from xetra.adapters.siem.elastic import ElasticAdapter
from xetra.adapters.soar.tines import TinesAdapter
from xetra.adapters.soar.xsoar import XSOARAdapter
from xetra.adapters.edr.crowdstrike import CrowdStrikeAdapter
from xetra.adapters.edr.defender import DefenderAdapter


@pytest.mark.parametrize("cls", [AttackIQAdapter, PenteraAdapter, SafeBreachAdapter, CymulateAdapter])
def test_bas_adapters_unconfigured_by_default(cls):
    a = cls()
    assert a.is_configured() is False
    with pytest.raises(RuntimeError):
        a.run_technique("T1595", {})


@pytest.mark.parametrize("cls", [SplunkAdapter, SentinelAdapter, ElasticAdapter])
def test_siem_adapters_unconfigured_by_default(cls):
    a = cls()
    assert a.is_configured() is False
    with pytest.raises(RuntimeError):
        a.check_alert("T1595")


@pytest.mark.parametrize("cls", [TinesAdapter, XSOARAdapter])
def test_soar_adapters_unconfigured_by_default(cls):
    a = cls()
    assert a.is_configured() is False
    with pytest.raises(RuntimeError):
        a.trigger_playbook("some-playbook", {})


@pytest.mark.parametrize("cls", [CrowdStrikeAdapter, DefenderAdapter])
def test_edr_adapters_unconfigured_by_default(cls):
    a = cls()
    assert a.is_configured() is False
    with pytest.raises(RuntimeError):
        a.get_coverage_report()
