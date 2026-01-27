import json
import logging
import asyncio
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import re
import yaml
import os
from pathlib import Path
from pulp import PULP_CBC_CMD
from dateutil.parser import isoparse

# For optimization
try:
    from pulp import LpProblem, LpMinimize, LpVariable, LpBinary, lpSum, LpStatus, value
    HAS_PULP = True
except ImportError:
    HAS_PULP = False
    print("Warning: PuLP not available. Using greedy heuristics for optimization.")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def ensure_utc(ts: str) -> datetime:
    """Convert any ISO 8601 string to timezone-aware UTC datetime."""
    if not ts:
        return datetime.now(timezone.utc)
    # Remove trailing Z if there’s already an offset
    if ts.endswith("Z") and "+" in ts:
        ts = ts[:-1]
    dt = isoparse(ts)
    return dt.astimezone(timezone.utc)

@dataclass
class NormalizedEvent:
    """Normalized telemetry event across all cloud providers"""
    timestamp: datetime
    function_id: str
    caller_principal: str
    resource_accessed: str
    api_action: str
    invocation_context: Dict[str, Any]
    payload_metadata: Dict[str, Any]
    cloud_provider: str
    confidence_score: float = 1.0

@dataclass
class UsageProfile:
    """Per-function resource usage profile"""
    function_id: str
    actions_observed: Set[str] = field(default_factory=set)
    resources_accessed: Set[str] = field(default_factory=set)
    frequency_map: Dict[str, int] = field(default_factory=dict)
    temporal_patterns: Dict[str, List[datetime]] = field(default_factory=dict)
    outlier_accesses: Set[str] = field(default_factory=set)
    risk_score: float = 0.0

@dataclass
class PolicyRule:
    """Individual policy rule"""
    action: str
    resource: str
    condition: Optional[Dict[str, Any]] = None
    effect: str = "Allow"

@dataclass
class SynthesizedPolicy:
    """Generated least-privilege policy for a function"""
    function_id: str
    cloud_provider: str
    rules: List[PolicyRule]
    risk_reduction: float
    evidence: List[str]
    iac_snippets: Dict[str, str] = field(default_factory=dict)

class MultiCloudTelemetryCollector:
    """Collects and normalizes telemetry from multiple cloud providers"""
    
    def __init__(self):
        self.events: List[NormalizedEvent] = []
        self.retention_days = 30
        
    def normalize_aws_cloudtrail(self, raw_event: Dict) -> NormalizedEvent:
        """Normalize AWS CloudTrail event"""
        return NormalizedEvent(
            timestamp = ensure_utc(raw_event.get("eventTime")),
            function_id=raw_event.get('resources', [{}])[0].get('ARN', '').split(':')[-1],
            caller_principal=raw_event.get('userIdentity', {}).get('arn', ''),
            resource_accessed=raw_event.get('resources', [{}])[0].get('ARN', ''),
            api_action=f"{raw_event.get('eventSource', '')}:{raw_event.get('eventName', '')}",
            invocation_context={
                'sourceIPAddress': raw_event.get('sourceIPAddress'),
                'userAgent': raw_event.get('userAgent'),
                'requestID': raw_event.get('requestID')
            },
            payload_metadata={'eventSource': raw_event.get('eventSource')},
            cloud_provider='aws'
        )
    
    def normalize_azure_activity(self, raw_event: Dict) -> NormalizedEvent:
        """Normalize Azure Activity Log event"""
        return NormalizedEvent(
            timestamp = ensure_utc(raw_event.get("eventTimestamp")),
            function_id=raw_event.get('resourceId', '').split('/')[-1],
            caller_principal=raw_event.get('caller', ''),
            resource_accessed=raw_event.get('resourceId', ''),
            api_action=f"{raw_event.get('resourceProviderName', '')}:{raw_event.get('operationName', '')}",
            invocation_context={
                'correlationId': raw_event.get('correlationId'),
                'subscriptionId': raw_event.get('subscriptionId')
            },
            payload_metadata={'category': raw_event.get('category')},
            cloud_provider='azure'
        )
    
    def normalize_gcp_audit(self, raw_event: Dict) -> NormalizedEvent:
        """Normalize GCP Audit Log event"""
        return NormalizedEvent(
            timestamp = ensure_utc(raw_event.get("timestamp")),
            function_id=raw_event.get('resource', {}).get('labels', {}).get('function_name', ''),
            caller_principal=raw_event.get('authenticationInfo', {}).get('principalEmail', ''),
            resource_accessed=raw_event.get('resourceName', ''),
            api_action=f"{raw_event.get('serviceName', '')}:{raw_event.get('methodName', '')}",
            invocation_context={
                'requestMetadata': raw_event.get('requestMetadata', {}),
                'insertId': raw_event.get('insertId')
            },
            payload_metadata={'severity': raw_event.get('severity')},
            cloud_provider='gcp'
        )
    
    def collect_events(self, raw_events: List[Dict], provider: str) -> int:
        """Collect and normalize events from a cloud provider"""
        normalized_count = 0
        
        for raw_event in raw_events:
            try:
                if provider == 'aws':
                    event = self.normalize_aws_cloudtrail(raw_event)
                elif provider == 'azure':
                    event = self.normalize_azure_activity(raw_event)
                elif provider == 'gcp':
                    event = self.normalize_gcp_audit(raw_event)
                else:
                    continue
                
                self.events.append(event)
                normalized_count += 1
                
            except Exception as e:
                logger.warning(f"Failed to normalize event from {provider}: {e}")
                continue
        
        # Cleanup old events
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        self.events = [e for e in self.events if e.timestamp > cutoff_date]
        
        logger.info(f"Normalized {normalized_count} events from {provider}")
        return normalized_count

class WorkflowAnalyzer:
    """Analyzes serverless workflow structure from IaC and static code"""
    
    def __init__(self):
        self.workflow_graph = {}
        self.function_manifests = {}
    
    def parse_terraform(self, terraform_content: str) -> Dict:
        """Extract serverless functions from Terraform configuration"""
        functions = {}
        
        # Simple regex-based parsing (in production, use proper HCL parser)
        aws_lambda_pattern = r'resource\s+"aws_lambda_function"\s+"([^"]+)"\s*{([^}]+)}'
        azure_function_pattern = r'resource\s+"azurerm_function_app"\s+"([^"]+)"\s*{([^}]+)}'
        gcp_function_pattern = r'resource\s+"google_cloudfunctions_function"\s+"([^"]+)"\s*{([^}]+)}'
        
        for pattern, provider in [(aws_lambda_pattern, 'aws'), 
                                 (azure_function_pattern, 'azure'),
                                 (gcp_function_pattern, 'gcp')]:
            matches = re.findall(pattern, terraform_content, re.DOTALL)
            for name, config in matches:
                functions[f"{provider}_{name}"] = {
                    'provider': provider,
                    'name': name,
                    'config': config,
                    'declared_resources': self._extract_resources_from_config(config)
                }
        
        return functions
    
    def _extract_resources_from_config(self, config: str) -> Set[str]:
        """Extract declared resources from function configuration"""
        resources = set()
        
        # Look for resource references in configuration
        resource_patterns = [
            r'arn:aws:[^"]+',
            r'/subscriptions/[^"]+',
            r'projects/[^"]+/[^"]+',
            r'\$\{[^}]*resource\.[^}]+\}'
        ]
        
        for pattern in resource_patterns:
            matches = re.findall(pattern, config)
            resources.update(matches)
        
        return resources
    
    def build_workflow_graph(self, functions: Dict, events: List[NormalizedEvent]) -> Dict:
        """Build serverless workflow dependency graph"""
        graph = defaultdict(lambda: {'dependencies': set(), 'dependents': set()})
        
        # Add static dependencies from IaC
        for func_id, func_info in functions.items():
            graph[func_id]['static_resources'] = func_info.get('declared_resources', set())
        
        # Add runtime dependencies from observed events
        for event in events:
            if event.function_id:
                graph[event.function_id]['runtime_resources'] = \
                    graph[event.function_id].get('runtime_resources', set())
                graph[event.function_id]['runtime_resources'].add(event.resource_accessed)
        
        return dict(graph)

class BehaviorProfiler:
    """Profiles function behavior and identifies usage patterns"""
    
    def __init__(self):
        self.profiles: Dict[str, UsageProfile] = {}
        self.outlier_threshold = 0.05  # 5% threshold for outlier detection
    
    def build_usage_profile(self, function_id: str, events: List[NormalizedEvent]) -> UsageProfile:
        """Build usage profile for a specific function"""
        function_events = [e for e in events if e.function_id == function_id]
        
        profile = UsageProfile(function_id=function_id)
        
        # Aggregate observed actions and resources
        for event in function_events:
            profile.actions_observed.add(event.api_action)
            profile.resources_accessed.add(event.resource_accessed)
            
            key = f"{event.api_action}:{event.resource_accessed}"
            profile.frequency_map[key] = profile.frequency_map.get(key, 0) + 1
            
            if key not in profile.temporal_patterns:
                profile.temporal_patterns[key] = []
            profile.temporal_patterns[key].append(event.timestamp)
        
        # Identify outliers (infrequent accesses)
        total_accesses = sum(profile.frequency_map.values())
        for key, count in profile.frequency_map.items():
            frequency = count / total_accesses if total_accesses > 0 else 0
            if frequency < self.outlier_threshold:
                profile.outlier_accesses.add(key)
        
        # Calculate risk score based on sensitive permissions and outliers
        profile.risk_score = self._calculate_risk_score(profile)
        
        self.profiles[function_id] = profile
        return profile
    
    def _calculate_risk_score(self, profile: UsageProfile) -> float:
        """Calculate risk score for a usage profile"""
        risk = 0.0
        
        # High-risk actions
        high_risk_patterns = [
            r'.*:PassRole',
            r'.*:\*',
            r'.*:Delete.*',
            r'.*:Create.*Policy',
            r'.*:Attach.*Policy'
        ]
        
        for action in profile.actions_observed:
            for pattern in high_risk_patterns:
                if re.match(pattern, action, re.IGNORECASE):
                    risk += 1.0
        
        # Outlier penalty
        risk += len(profile.outlier_accesses) * 0.5
        
        # Cross-account access penalty
        for resource in profile.resources_accessed:
            if '::' in resource and 'arn:aws' in resource:
                # Different account ID
                account_ids = re.findall(r':(\d{12}):', resource)
                if len(set(account_ids)) > 1:
                    risk += 0.5
        
        return min(risk, 10.0)  # Cap at 10

class PolicySynthesizer:
    """Core policy synthesis engine"""
    
    def __init__(self):
        self.policy_templates = self._load_policy_templates()
    
    def _load_policy_templates(self) -> Dict:
        """Load policy templates for different cloud providers"""
        return {
            'aws': {
                'iam_policy': {
                    'Version': '2012-10-17',
                    'Statement': []
                },
                'trust_policy': {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Principal': {'Service': 'lambda.amazonaws.com'},
                        'Action': 'sts:AssumeRole'
                    }]
                }
            },
            'azure': {
                'custom_role': {
                    'Name': '',
                    'Description': '',
                    'Actions': [],
                    'NotActions': [],
                    'AssignableScopes': []
                }
            },
            'gcp': {
                'custom_role': {
                    'title': '',
                    'description': '',
                    'includedPermissions': [],
                    'stage': 'GA'
                }
            }
        }
    
    def synthesize_policy(self, function_id: str, profile: UsageProfile, 
                         workflow_graph: Dict) -> SynthesizedPolicy:
        """Synthesize least-privilege policy for a function"""
        
        # Determine cloud provider from function ID
        provider = self._detect_provider(function_id)
        
        # Get conservative baseline from static analysis
        static_resources = workflow_graph.get(function_id, {}).get('static_resources', set())
        runtime_resources = workflow_graph.get(function_id, {}).get('runtime_resources', set())
        
        # Optimize permission set
        if HAS_PULP:
            optimized_rules = self._optimize_with_ilp(profile, static_resources, runtime_resources)
        else:
            optimized_rules = self._optimize_with_greedy(profile, static_resources, runtime_resources)
        
        # Calculate risk reduction
        risk_reduction = self._calculate_risk_reduction(profile, optimized_rules)
        
        # Generate evidence
        evidence = [f"Observed {len(profile.actions_observed)} unique actions",
                   f"Accessed {len(profile.resources_accessed)} resources",
                   f"Risk score: {profile.risk_score:.2f}"]
        
        return SynthesizedPolicy(
            function_id=function_id,
            cloud_provider=provider,
            rules=optimized_rules,
            risk_reduction=risk_reduction,
            evidence=evidence
        )
    
    def _detect_provider(self, function_id: str) -> str:
        """Detect cloud provider from function ID"""
        if function_id.startswith('aws_') or 'lambda' in function_id.lower():
            return 'aws'
        elif function_id.startswith('azure_') or 'azurerm' in function_id.lower():
            return 'azure'
        elif function_id.startswith('gcp_') or 'google' in function_id.lower():
            return 'gcp'
        return 'aws'  # Default
    
    def _optimize_with_ilp(self, profile: UsageProfile, static_resources: Set, 
                          runtime_resources: Set) -> List[PolicyRule]:
        """Optimize using Integer Linear Programming"""
        
        prob = LpProblem("PolicyOptimization", LpMinimize)
        
        # Create binary variables for each action-resource pair
        all_pairs = set()
        for action in profile.actions_observed:
            for resource in profile.resources_accessed:
                all_pairs.add((action, resource))
        
        # Add static resources
        for action in profile.actions_observed:
            for resource in static_resources:
                all_pairs.add((action, resource))
        
        variables = {}
        for action, resource in all_pairs:
            var_name = f"{action}_{hashlib.md5(resource.encode()).hexdigest()[:8]}"
            variables[(action, resource)] = LpVariable(var_name, cat=LpBinary)
        
        # Objective: minimize total permissions weighted by risk
        risk_weights = {}
        for action, resource in all_pairs:
            weight = 1.0
            if any(pattern in action.lower() for pattern in ['*', 'delete', 'passrole']):
                weight = 2.0
            risk_weights[(action, resource)] = weight
        
        prob += lpSum([risk_weights[(action, resource)] * variables[(action, resource)] 
                      for action, resource in all_pairs])
        
        # Constraints: ensure all observed accesses are covered
        for key in profile.frequency_map.keys():
            if ':' in key:
                action, resource = key.split(':', 1)
                if (action, resource) in variables:
                    prob += variables[(action, resource)] >= 1
        
        # Solve
        # prob.solve(msg=0)  # Silent solve
        prob.solve(PULP_CBC_CMD(msg=False))
        
        rules = []
        if prob.status == 1:  # Optimal solution found
            for (action, resource), var in variables.items():
                if value(var) == 1:
                    rules.append(PolicyRule(action=action, resource=resource))
        
        return rules if rules else self._optimize_with_greedy(profile, static_resources, runtime_resources)
    
    def _optimize_with_greedy(self, profile: UsageProfile, static_resources: Set, 
                             runtime_resources: Set) -> List[PolicyRule]:
        """Optimize using greedy set cover heuristic"""
        rules = []
        
        # Add rules for observed accesses
        for key in profile.frequency_map.keys():
            if ':' in key:
                action, resource = key.split(':', 1)
                rules.append(PolicyRule(action=action, resource=resource))
        
        # Add rules for static resources with observed actions
        for action in profile.actions_observed:
            for resource in static_resources:
                if resource not in profile.resources_accessed:
                    rules.append(PolicyRule(action=action, resource=resource))
        
        return rules
    
    def _calculate_risk_reduction(self, profile: UsageProfile, rules: List[PolicyRule]) -> float:
        """Calculate risk reduction percentage"""
        # Simplified calculation - in practice, compare against current overprivileged policy
        current_risk = profile.risk_score
        new_risk = len([r for r in rules if any(pattern in r.action for pattern in ['*', 'Delete', 'PassRole'])]) * 0.5
        
        reduction = max(0, (current_risk - new_risk) / max(current_risk, 1.0)) * 100
        return min(reduction, 100.0)

class IaCAdapter:
    """Translates policies into Infrastructure as Code snippets"""
    
    def generate_terraform_aws(self, policy: SynthesizedPolicy) -> str:
        """Generate Terraform for AWS IAM policy"""
        statements = []
        
        for rule in policy.rules:
            statements.append({
                'Effect': rule.effect,
                'Action': [rule.action],
                'Resource': [rule.resource]
            })
        
        policy_doc = {
            'Version': '2012-10-17',
            'Statement': statements
        }
        
        terraform = f'''
resource "aws_iam_policy" "{policy.function_id}_policy" {{
  name        = "{policy.function_id}-least-privilege-policy"
  description = "Auto-generated least-privilege policy for {policy.function_id}"
  
  policy = jsonencode({json.dumps(policy_doc, indent=2)})
}}

resource "aws_iam_role_policy_attachment" "{policy.function_id}_attachment" {{
  policy_arn = aws_iam_policy.{policy.function_id}_policy.arn
  role       = aws_iam_role.{policy.function_id}_role.name
}}
'''
        return terraform.strip()
    
    def generate_terraform_azure(self, policy: SynthesizedPolicy) -> str:
        """Generate Terraform for Azure custom role"""
        actions = [rule.action for rule in policy.rules]
        
        terraform = f'''
resource "azurerm_role_definition" "{policy.function_id}_role" {{
  name        = "{policy.function_id}-least-privilege-role"
  scope       = data.azurerm_subscription.current.id
  description = "Auto-generated least-privilege role for {policy.function_id}"

  permissions {{
    actions = {json.dumps(actions)}
    not_actions = []
  }}

  assignable_scopes = [
    data.azurerm_subscription.current.id,
  ]
}}
'''
        return terraform.strip()
    
    def generate_terraform_gcp(self, policy: SynthesizedPolicy) -> str:
        """Generate Terraform for GCP custom role"""
        permissions = [rule.action for rule in policy.rules]
        
        terraform = f'''
resource "google_project_iam_custom_role" "{policy.function_id}_role" {{
  role_id     = "{policy.function_id.replace('-', '_')}_least_privilege"
  title       = "{policy.function_id} Least Privilege Role"
  description = "Auto-generated least-privilege role for {policy.function_id}"
  permissions = {json.dumps(permissions)}
}}
'''
        return terraform.strip()
    
    def generate_iac_snippets(self, policy: SynthesizedPolicy) -> Dict[str, str]:
        """Generate IaC snippets for all supported formats"""
        snippets = {}
        
        if policy.cloud_provider == 'aws':
            snippets['terraform'] = self.generate_terraform_aws(policy)
        elif policy.cloud_provider == 'azure':
            snippets['terraform'] = self.generate_terraform_azure(policy)
        elif policy.cloud_provider == 'gcp':
            snippets['terraform'] = self.generate_terraform_gcp(policy)
        
        return snippets

class SandboxValidator:
    """Validates synthesized policies in a sandbox environment"""
    
    def __init__(self):
        self.test_results = []
    
    async def validate_policy(self, policy: SynthesizedPolicy, 
                            test_workload: List[Dict]) -> Dict[str, Any]:
        """Validate policy by running test workload"""
        
        logger.info(f"Validating policy for {policy.function_id}")
        
        # Simulate policy deployment and testing
        results = {
            'function_id': policy.function_id,
            'policy_valid': True,
            'failed_operations': [],
            'performance_impact': 0.0,
            'security_score': 0.0
        }
        
        # Simulate running test operations
        for test_op in test_workload:
            if not self._would_policy_allow(policy, test_op):
                results['failed_operations'].append(test_op)
                results['policy_valid'] = False
        
        # Calculate security score improvement
        results['security_score'] = policy.risk_reduction
        
        self.test_results.append(results)
        
        logger.info(f"Validation complete for {policy.function_id}: "
                   f"Valid={results['policy_valid']}, "
                   f"Security Score={results['security_score']:.2f}%")
        
        return results
    
    def _would_policy_allow(self, policy: SynthesizedPolicy, operation: Dict) -> bool:
        """Check if policy would allow a specific operation"""
        required_action = operation.get('action', '')
        required_resource = operation.get('resource', '')
        
        for rule in policy.rules:
            if (rule.action == required_action or rule.action == '*') and \
               (rule.resource == required_resource or rule.resource == '*'):
                return rule.effect == 'Allow'
        
        return False

class ContinuousMonitor:
    """Monitors deployed policies and triggers adaptations"""
    
    def __init__(self):
        self.monitoring_active = False
        self.adaptation_threshold = 5  # New accesses before triggering update
        
    async def start_monitoring(self, adapol_system):
        """Start continuous monitoring loop"""
        self.monitoring_active = True
        logger.info("Starting continuous monitoring")
        
        while self.monitoring_active:
            try:
                await self._monitor_cycle(adapol_system)
                await asyncio.sleep(300)  # 5-minute monitoring cycles
            except Exception as e:
                logger.error(f"Monitoring cycle failed: {e}")
                await asyncio.sleep(60)  # Shorter retry interval
    
    async def _monitor_cycle(self, adapol_system):
        """Single monitoring cycle"""
        # Collect new events
        new_events_count = 0
        
        # Check for policy violations or new access patterns
        for function_id, profile in adapol_system.profiler.profiles.items():
            current_accesses = len(profile.frequency_map)
            
            # Simulate detecting new accesses (in real implementation, query fresh logs)
            if hasattr(profile, '_last_access_count'):
                new_accesses = current_accesses - profile._last_access_count
                if new_accesses >= self.adaptation_threshold:
                    logger.info(f"Triggering policy update for {function_id} "
                               f"due to {new_accesses} new accesses")
                    await self._trigger_adaptation(adapol_system, function_id)
            
            profile._last_access_count = current_accesses
    
    async def _trigger_adaptation(self, adapol_system, function_id: str):
        """Trigger policy adaptation for a specific function"""
        try:
            # Re-profile the function
            events = [e for e in adapol_system.collector.events if e.function_id == function_id]
            profile = adapol_system.profiler.build_usage_profile(function_id, events)
            
            # Re-synthesize policy
            policy = adapol_system.synthesizer.synthesize_policy(
                function_id, profile, adapol_system.analyzer.workflow_graph
            )
            
            # Generate new IaC
            policy.iac_snippets = adapol_system.iac_adapter.generate_iac_snippets(policy)
            
            # Validate in sandbox
            test_workload = [{'action': action, 'resource': resource} 
                           for action in profile.actions_observed 
                           for resource in profile.resources_accessed]
            
            validation_result = await adapol_system.validator.validate_policy(policy, test_workload)
            
            if validation_result['policy_valid']:
                logger.info(f"Policy adaptation successful for {function_id}")
                # In real implementation, would create PR or deploy via CI/CD
            else:
                logger.warning(f"Policy adaptation failed validation for {function_id}")
                
        except Exception as e:
            logger.error(f"Policy adaptation failed for {function_id}: {e}")
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring_active = False
        logger.info("Stopping continuous monitoring")

class AdaPolSystem:
    """Main AdaPol system orchestrating all components"""
    
    def __init__(self):
        self.collector = MultiCloudTelemetryCollector()
        self.analyzer = WorkflowAnalyzer()
        self.profiler = BehaviorProfiler()
        self.synthesizer = PolicySynthesizer()
        self.iac_adapter = IaCAdapter()
        self.validator = SandboxValidator()
        self.monitor = ContinuousMonitor()
        
        self.policies: Dict[str, SynthesizedPolicy] = {}
        
    def load_sample_data(self):
        """Load sample data for demonstration"""
        # Sample CloudTrail events
        sample_aws_events = [
            {
                'eventTime': '2024-01-15T10:30:00Z',
                'eventSource': 's3.amazonaws.com',
                'eventName': 'GetObject',
                'userIdentity': {'arn': 'arn:aws:iam::123456789012:role/lambda-role'},
                'resources': [{'ARN': 'arn:aws:s3:::my-bucket/data.json'}],
                'sourceIPAddress': '10.0.0.1',
                'userAgent': 'aws-sdk-python',
                'requestID': 'req-12345'
            },
            {
                'eventTime': '2024-01-15T10:31:00Z',
                'eventSource': 'dynamodb.amazonaws.com',
                'eventName': 'PutItem',
                'userIdentity': {'arn': 'arn:aws:iam::123456789012:role/lambda-role'},
                'resources': [{'ARN': 'arn:aws:dynamodb:us-east-1:123456789012:table/Orders'}],
                'sourceIPAddress': '10.0.0.1',
                'userAgent': 'aws-sdk-python',
                'requestID': 'req-12346'
            }
        ]
        
        # Sample Terraform configuration
        sample_terraform = '''
resource "aws_lambda_function" "order_processor" {
  function_name = "order-processor"
  role         = aws_iam_role.lambda_role.arn
  handler      = "index.handler"
  runtime      = "python3.9"
}

resource "aws_s3_bucket" "data_bucket" {
  bucket = "my-bucket"
}

resource "aws_dynamodb_table" "orders" {
  name           = "Orders"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "OrderId"
}
'''
        
        # Process sample data
        self.collector.collect_events(sample_aws_events, 'aws')
        functions = self.analyzer.parse_terraform(sample_terraform)
        self.analyzer.function_manifests = functions
        self.analyzer.workflow_graph = self.analyzer.build_workflow_graph(
            functions, self.collector.events
        )
        
        logger.info("Sample data loaded successfully")
    
    async def run_full_analysis(self) -> Dict[str, SynthesizedPolicy]:
        """Run complete policy analysis and synthesis"""
        logger.info("Starting full AdaPol analysis")
        
        # Build usage profiles for all functions
        for function_id in self.analyzer.workflow_graph.keys():
            events = [e for e in self.collector.events if e.function_id == function_id]
            if events:  # Only profile functions with observed events
                profile = self.profiler.build_usage_profile(function_id, events)
                
                # Synthesize policy for this function
                policy = self.synthesizer.synthesize_policy(
                    function_id, profile, self.analyzer.workflow_graph
                )
                
                # Generate IaC snippets
                policy.iac_snippets = self.iac_adapter.generate_iac_snippets(policy)
                
                # Validate policy
                test_workload = [
                    {'action': action, 'resource': resource}
                    for action in profile.actions_observed
                    for resource in profile.resources_accessed
                ]
                
                validation_result = await self.validator.validate_policy(policy, test_workload)
                
                if validation_result['policy_valid']:
                    self.policies[function_id] = policy
                    logger.info(f"Policy synthesized and validated for {function_id}")
                else:
                    logger.warning(f"Policy validation failed for {function_id}")
        
        logger.info(f"Analysis complete. Generated {len(self.policies)} policies")
        return self.policies
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive analysis report"""
        report = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'summary': {
                'total_functions': len(self.analyzer.workflow_graph),
                'policies_generated': len(self.policies),
                'total_events_processed': len(self.collector.events),
                'average_risk_reduction': 0.0
            },
            'function_details': {},
            'validation_results': self.validator.test_results
        }
        
        total_risk_reduction = 0.0
        
        for function_id, policy in self.policies.items():
            profile = self.profiler.profiles.get(function_id)
            if profile:
                report['function_details'][function_id] = {
                    'cloud_provider': policy.cloud_provider,
                    'actions_observed': len(profile.actions_observed),
                    'resources_accessed': len(profile.resources_accessed),
                    'risk_score': profile.risk_score,
                    'risk_reduction_percent': policy.risk_reduction,
                    'policy_rules_count': len(policy.rules),
                    'outlier_accesses': len(profile.outlier_accesses),
                    'evidence': policy.evidence
                }
                total_risk_reduction += policy.risk_reduction
        
        if self.policies:
            report['summary']['average_risk_reduction'] = total_risk_reduction / len(self.policies)
        
        return report
    
    def export_policies(self, output_dir: str = "adapol_output"):
        """Export all generated policies and IaC snippets"""
        Path(output_dir).mkdir(exist_ok=True)
        
        # Export individual policy files
        for function_id, policy in self.policies.items():
            function_dir = Path(output_dir) / function_id
            function_dir.mkdir(exist_ok=True)
            
            # Export policy JSON
            policy_json = {
                'function_id': policy.function_id,
                'cloud_provider': policy.cloud_provider,
                'rules': [
                    {
                        'action': rule.action,
                        'resource': rule.resource,
                        'effect': rule.effect,
                        'condition': rule.condition
                    }
                    for rule in policy.rules
                ],
                'risk_reduction': policy.risk_reduction,
                'evidence': policy.evidence
            }
            
            with open(function_dir / "policy.json", 'w') as f:
                json.dump(policy_json, f, indent=2)
            
            # Export IaC snippets
            for format_name, snippet in policy.iac_snippets.items():
                with open(function_dir / f"{format_name}.tf", 'w') as f:
                    f.write(snippet)
        
        # Export comprehensive report
        report = self.generate_report()
        with open(Path(output_dir) / "analysis_report.json", 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Export summary Terraform file
        self._export_combined_terraform(output_dir)
        
        logger.info(f"Policies exported to {output_dir}")
    
    def _export_combined_terraform(self, output_dir: str):
        """Export a combined Terraform file with all policies"""
        terraform_content = []
        terraform_content.append("# AdaPol Generated Least-Privilege Policies")
        terraform_content.append("# Generated at: " + datetime.now(timezone.utc).isoformat())
        terraform_content.append("")
        
        for function_id, policy in self.policies.items():
            terraform_content.append(f"# Policy for {function_id}")
            if 'terraform' in policy.iac_snippets:
                terraform_content.append(policy.iac_snippets['terraform'])
                terraform_content.append("")
        
        with open(Path(output_dir) / "all_policies.tf", 'w') as f:
            f.write('\n'.join(terraform_content))
    
    async def start_continuous_monitoring(self):
        """Start continuous monitoring and adaptation"""
        await self.monitor.start_monitoring(self)
    
    def stop_continuous_monitoring(self):
        """Stop continuous monitoring"""
        self.monitor.stop_monitoring()

# CLI Interface and Demo
class AdaPolCLI:
    """Command-line interface for AdaPol"""
    
    def __init__(self):
        self.adapol = AdaPolSystem()
    
    async def demo_run(self):
        """Run a complete demonstration"""
        print("🚀 AdaPol: Adaptive Multi-Cloud Least-Privilege Policy Generator")
        print("=" * 60)
        
        print("\n📊 Loading sample data...")
        self.adapol.load_sample_data()
        
        print("\n🔍 Running policy analysis...")
        policies = await self.adapol.run_full_analysis()
        
        print(f"\n✅ Analysis complete! Generated {len(policies)} policies")
        
        print("\n📋 Policy Summary:")
        for function_id, policy in policies.items():
            profile = self.adapol.profiler.profiles.get(function_id)
            if profile:
                print(f"  • {function_id}:")
                print(f"    - Provider: {policy.cloud_provider}")
                print(f"    - Rules: {len(policy.rules)}")
                print(f"    - Risk Reduction: {policy.risk_reduction:.1f}%")
                print(f"    - Actions Observed: {len(profile.actions_observed)}")
                print(f"    - Resources Accessed: {len(profile.resources_accessed)}")
        
        print("\n💾 Exporting policies...")
        self.adapol.export_policies()
        
        print("\n📊 Generating detailed report...")
        report = self.adapol.generate_report()
        
        print(f"\n📈 Summary Statistics:")
        print(f"  • Total Functions Analyzed: {report['summary']['total_functions']}")
        print(f"  • Policies Generated: {report['summary']['policies_generated']}")
        print(f"  • Events Processed: {report['summary']['total_events_processed']}")
        print(f"  • Average Risk Reduction: {report['summary']['average_risk_reduction']:.1f}%")
        
        print("\n🔧 Sample Generated Terraform:")
        if policies:
            sample_policy = list(policies.values())[0]
            if 'terraform' in sample_policy.iac_snippets:
                print("```hcl")
                print(sample_policy.iac_snippets['terraform'][:500] + "...")
                print("```")
        
        print("\n✅ Demo complete! Check 'adapol_output' directory for full results.")
        
        # Optionally start monitoring
        response = input("\n🔄 Start continuous monitoring? (y/N): ").lower()
        if response == 'y':
            print("🔄 Starting continuous monitoring... (Press Ctrl+C to stop)")
            try:
                await self.adapol.start_continuous_monitoring()
            except KeyboardInterrupt:
                print("\n🛑 Stopping monitoring...")
                self.adapol.stop_continuous_monitoring()
    
    def run_cli(self):
        """Run the CLI interface"""
        import argparse
        
        parser = argparse.ArgumentParser(description='AdaPol: Multi-Cloud Serverless Policy Generator')
        parser.add_argument('--demo', action='store_true', help='Run demonstration with sample data')
        parser.add_argument('--terraform', type=str, help='Path to Terraform file to analyze')
        parser.add_argument('--events', type=str, help='Path to JSON file with cloud events')
        parser.add_argument('--provider', type=str, choices=['aws', 'azure', 'gcp'], 
                           default='aws', help='Cloud provider for events')
        parser.add_argument('--output', type=str, default='adapol_output', 
                           help='Output directory for generated policies')
        parser.add_argument('--monitor', action='store_true', 
                           help='Start continuous monitoring after analysis')
        
        args = parser.parse_args()
        
        if args.demo:
            asyncio.run(self.demo_run())
        else:
            asyncio.run(self._run_analysis(args))
    
    async def _run_analysis(self, args):
        """Run analysis with provided data"""
        print("🚀 AdaPol: Starting Analysis...")
        
        # Load Terraform if provided
        if args.terraform and os.path.exists(args.terraform):
            with open(args.terraform, 'r') as f:
                terraform_content = f.read()
            
            functions = self.adapol.analyzer.parse_terraform(terraform_content)
            self.adapol.analyzer.function_manifests = functions
            print(f"📋 Loaded {len(functions)} functions from Terraform")
        
        # Load events if provided
        if args.events and os.path.exists(args.events):
            with open(args.events, 'r') as f:
                events_data = json.load(f)
            
            if isinstance(events_data, list):
                self.adapol.collector.collect_events(events_data, args.provider)
                print(f"📊 Loaded {len(events_data)} events from {args.provider}")
            else:
                print("❌ Events file must contain a JSON array of events")
                return
        
        # Build workflow graph
        if hasattr(self.adapol.analyzer, 'function_manifests'):
            self.adapol.analyzer.workflow_graph = self.adapol.analyzer.build_workflow_graph(
                self.adapol.analyzer.function_manifests, self.adapol.collector.events
            )
        
        # Run analysis
        policies = await self.adapol.run_full_analysis()
        
        if policies:
            print(f"✅ Generated {len(policies)} policies")
            
            # Export results
            self.adapol.export_policies(args.output)
            print(f"💾 Results exported to {args.output}")
            
            # Start monitoring if requested
            if args.monitor:
                print("🔄 Starting continuous monitoring... (Press Ctrl+C to stop)")
                try:
                    await self.adapol.start_continuous_monitoring()
                except KeyboardInterrupt:
                    print("\n🛑 Stopping monitoring...")
                    self.adapol.stop_continuous_monitoring()
        else:
            print("❌ No policies generated. Check your input data.")

# Sample data generators for testing
class SampleDataGenerator:
    """Generates sample data for testing and demonstration"""
    
    @staticmethod
    def generate_sample_events(num_events: int = 50, provider: str = 'aws') -> List[Dict]:
        """Generate sample cloud events for testing"""
        events = []
        
        function_names = ['order-processor', 'payment-handler', 'notification-service']
        actions = {
            'aws': [
                ('s3.amazonaws.com', 'GetObject'),
                ('s3.amazonaws.com', 'PutObject'),
                ('dynamodb.amazonaws.com', 'PutItem'),
                ('dynamodb.amazonaws.com', 'GetItem'),
                ('lambda.amazonaws.com', 'InvokeFunction'),
                ('sns.amazonaws.com', 'Publish')
            ],
            'azure': [
                ('Microsoft.Storage', 'storageAccounts/read'),
                ('Microsoft.Storage', 'storageAccounts/write'),
                ('Microsoft.DocumentDB', 'databaseAccounts/readMetadata'),
                ('Microsoft.Web', 'sites/functions/action')
            ],
            'gcp': [
                ('storage.googleapis.com', 'storage.objects.get'),
                ('storage.googleapis.com', 'storage.objects.create'),
                ('firestore.googleapis.com', 'google.firestore.v1.Firestore.Write'),
                ('cloudfunctions.googleapis.com', 'cloudfunctions.functions.call')
            ]
        }
        
        import random
        from datetime import datetime, timedelta
        
        base_time = datetime.now(timezone.utc) - timedelta(days=7)
        
        for i in range(num_events):
            function_name = random.choice(function_names)
            event_source, event_name = random.choice(actions[provider])
            
            if provider == 'aws':
                event = {
                    'eventTime': (base_time + timedelta(seconds=i*100)).isoformat() + 'Z',
                    'eventSource': event_source,
                    'eventName': event_name,
                    'userIdentity': {'arn': f'arn:aws:iam::123456789012:role/{function_name}-role'},
                    'resources': [{'ARN': f'arn:aws:s3:::my-bucket/data-{i}.json'}],
                    'sourceIPAddress': f'10.0.0.{random.randint(1, 255)}',
                    'userAgent': 'aws-sdk-python',
                    'requestID': f'req-{uuid.uuid4().hex[:8]}'
                }
            elif provider == 'azure':
                event = {
                    'eventTimestamp': (base_time + timedelta(seconds=i*100)).isoformat(),
                    'resourceProviderName': event_source.split('.')[1],
                    'operationName': event_name,
                    'caller': f'{function_name}@example.com',
                    'resourceId': f'/subscriptions/sub-123/resourceGroups/rg-1/providers/{event_source}/accounts/{function_name}',
                    'correlationId': str(uuid.uuid4()),
                    'subscriptionId': 'sub-123',
                    'category': 'Action'
                }
            else:  # gcp
                event = {
                    'timestamp': (base_time + timedelta(seconds=i*100)).isoformat(),
                    'serviceName': event_source,
                    'methodName': event_name,
                    'authenticationInfo': {'principalEmail': f'{function_name}@project.iam.gserviceaccount.com'},
                    'resourceName': f'projects/my-project/buckets/my-bucket/objects/data-{i}.json',
                    'resource': {'labels': {'function_name': function_name}},
                    'insertId': str(uuid.uuid4()),
                    'severity': 'INFO'
                }
            
            events.append(event)
        
        return events
    
    @staticmethod
    def generate_sample_terraform(provider: str = 'aws') -> str:
        """Generate sample Terraform configuration"""
        
        if provider == 'aws':
            return '''
# Sample AWS Serverless Application
resource "aws_lambda_function" "order_processor" {
  function_name = "order-processor"
  role         = aws_iam_role.lambda_role.arn
  handler      = "index.handler"
  runtime      = "python3.9"
  
  environment {
    variables = {
      BUCKET_NAME = aws_s3_bucket.data_bucket.bucket
      TABLE_NAME  = aws_dynamodb_table.orders.name
    }
  }
}

resource "aws_lambda_function" "payment_handler" {
  function_name = "payment-handler"
  role         = aws_iam_role.lambda_role.arn
  handler      = "payment.handler"
  runtime      = "python3.9"
}

resource "aws_s3_bucket" "data_bucket" {
  bucket = "my-serverless-data-bucket"
}

resource "aws_dynamodb_table" "orders" {
  name           = "Orders"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "OrderId"
  
  attribute {
    name = "OrderId"
    type = "S"
  }
}

resource "aws_sns_topic" "notifications" {
  name = "order-notifications"
}
'''
        elif provider == 'azure':
            return '''
# Sample Azure Serverless Application
resource "azurerm_function_app" "order_processor" {
  name                = "order-processor-func"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  app_service_plan_id = azurerm_app_service_plan.main.id
  
  app_settings = {
    STORAGE_ACCOUNT_NAME = azurerm_storage_account.main.name
    COSMOS_DB_ENDPOINT   = azurerm_cosmosdb_account.main.endpoint
  }
}

resource "azurerm_storage_account" "main" {
  name                     = "orderstorage"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_cosmosdb_account" "main" {
  name                = "orders-cosmosdb"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"
}
'''
        else:  # gcp
            return '''
# Sample GCP Serverless Application
resource "google_cloudfunctions_function" "order_processor" {
  name        = "order-processor"
  runtime     = "python39"
  entry_point = "process_order"
  
  source_archive_bucket = google_storage_bucket.source.name
  source_archive_object = google_storage_bucket_object.source.name
  
  environment_variables = {
    BUCKET_NAME = google_storage_bucket.data.name
  }
}

resource "google_storage_bucket" "data" {
  name     = "my-serverless-data"
  location = "US"
}

resource "google_firestore_database" "orders" {
  project     = var.project
  name        = "(default)"
  location_id = "us-central"
  type        = "FIRESTORE_NATIVE"
}
'''

if __name__ == "__main__":
    # Check if running as script
    import sys
    
    if len(sys.argv) > 1:
        # Run CLI interface
        cli = AdaPolCLI()
        cli.run_cli()
    else:
        # Run demo
        print("🚀 AdaPol Demo Mode")
        print("Run with --help to see CLI options, or just run for demo")
        
        cli = AdaPolCLI()
        asyncio.run(cli.demo_run())