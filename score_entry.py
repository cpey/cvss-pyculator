from cvss_types import *

# Base Score
AttackVector = Vector.PHYSICAL
AttackComplexity = Complexity.HIGH
PrivilegesRequired = Privileges.NONE 
UserInteraction = Interaction.NONE
BaseScope = Scope.CHANGED
Confidentiality = CIA.HIGH
Integrity = CIA.HIGH
Availability = CIA.HIGH

# Temportal Score
ExploitCodeMaturity = Maturity.ND
RemediationLevel = Remediation.ND 
ReportConfidence = Confidence.ND 

# Environmental Score
ModifiedScope = Scope.ND
ConfidentialityRequirement = CIAR.ND
AvailabilityRequirement = CIAR.ND
IntegrityRequirement = CIAR.ND
ModifiedAttackVector = Vector.ND
ModifiedAttackComplexity = Complexity.ND
ModifiedPrivilegesRequired = Privileges.ND
ModifiedUserInteraction = Interaction.ND
ModifiedScope = Scope.ND
ModifiedConfidentiality = CIA.ND
ModifiedIntegrity = CIA.ND
ModifiedAvailability = CIA.ND
