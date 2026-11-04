"""Provider Adapters Package (Phase 8).

Exports production-minded adapters for SIEM, EDR, Identity, and Ticketing systems.
"""

from redloop.integrations.adapters.edr_crowdstrike import CrowdStrikeFalconAdapter
from redloop.integrations.adapters.edr_defender import DefenderForEndpointAdapter
from redloop.integrations.adapters.elastic import ElasticSecurityAdapter
from redloop.integrations.adapters.identity_ad import ActiveDirectoryAdapter
from redloop.integrations.adapters.identity_entra import EntraIDAdapter
from redloop.integrations.adapters.splunk import SplunkAdapter
from redloop.integrations.adapters.ticketing_jira import JiraAdapter
from redloop.integrations.adapters.ticketing_servicenow import ServiceNowAdapter
from redloop.integrations.adapters.wazuh import WazuhAdapter

__all__ = [
    "WazuhAdapter",
    "ElasticSecurityAdapter",
    "SplunkAdapter",
    "DefenderForEndpointAdapter",
    "CrowdStrikeFalconAdapter",
    "EntraIDAdapter",
    "ActiveDirectoryAdapter",
    "JiraAdapter",
    "ServiceNowAdapter",
]
