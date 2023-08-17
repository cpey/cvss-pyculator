#!/usr/bin/env python

# CVSS 3.1 calculator as specified by FIRST in
# https://www.first.org/cvss/v3.1/specification-document

import math
from cvss_types import *
from score_entry import *
from cvss_metric_values import Metric

def roundup(value):
    value = int(value * 100000)
    if (value % 10000) == 0:
        return value / 100000.0
    else:
        return (math.floor(value / 10000) + 1) / 10.0

# Base Score
if PrivilegesRequired == Privileges.LOW and BaseScope == Scope.CHANGED:
   PrivilegesRequired = Privileges.CH_LOW
if PrivilegesRequired == Privileges.HIGH and BaseScope == Scope.CHANGED:
   PrivilegesRequired = Privileges.CH_HIGH

iss = 1 - ((1 - Metric[Confidentiality]) * (1 - Metric[Integrity]) * (1 - Metric[Availability])) 

if BaseScope == Scope.UNCHANGED:
    impact = 6.42 * iss
if BaseScope == Scope.CHANGED:
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02)**15 
exploitability = (8.22 * Metric[AttackVector] * Metric[AttackComplexity] * 
                 Metric[PrivilegesRequired] * Metric[UserInteraction])
if impact <= 0:
    BaseScore = 0
elif BaseScope == Scope.UNCHANGED:
    BaseScore = roundup(min((impact+exploitability), 10))
elif BaseScope == Scope.CHANGED:
    BaseScore = roundup(min(1.08 * (impact+exploitability), 10))

# Temporal Score
TemporalScore = roundup(BaseScore * Metric[ExploitCodeMaturity] * 
                        Metric[RemediationLevel] * Metric[ReportConfidence])

# Environmental Score
if ModifiedAttackVector == Vector.ND: ModifiedAttackVector = AttackVector
if ModifiedAttackComplexity == Complexity.ND: ModifiedAttackComplexity = AttackComplexity
if ModifiedUserInteraction == Interaction.ND: ModifiedUserInteraction = UserInteraction
if ModifiedScope == Scope.ND: ModifiedScope = BaseScope
if ModifiedConfidentiality == CIA.ND: ModifiedConfidentiality = Confidentiality
if ModifiedIntegrity == CIA.ND: ModifiedIntegrity = Integrity
if ModifiedAvailability == CIA.ND: ModifiedAvailability = Availability
if ModifiedPrivilegesRequired == Privileges.ND: ModifiedPrivilegesRequired = PrivilegesRequired
if ModifiedPrivilegesRequired == Privileges.LOW and ModifiedScope == Scope.CHANGED:
    ModifiedPrivilegesRequired = Privileges.CH_LOW
if ModifiedPrivilegesRequired == Privileges.HIGH and ModifiedScope == Scope.CHANGED:
    ModifiedPrivilegesRequired = Privileges.CH_HIGH

miss = min(1 - ((1 - Metric[ConfidentialityRequirement] * Metric[ModifiedConfidentiality]) * 
                (1 - Metric[IntegrityRequirement]* Metric[ModifiedIntegrity]) * 
                (1 - Metric[AvailabilityRequirement]* Metric[ModifiedAvailability])), 0.915)

if (ModifiedScope == Scope.UNCHANGED):
    ModifiedImpact = 6.42 * miss

if (ModifiedScope == Scope.CHANGED):
    ModifiedImpact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02)**13

ModifiedExploitability = (8.22 * Metric[ModifiedAttackVector] * 
                                Metric[ModifiedAttackComplexity] * 
                                Metric[ModifiedPrivilegesRequired] * 
                                Metric[ModifiedUserInteraction])
if ModifiedImpact <= 0:
    EnvironmentalScore = 0
elif ModifiedScope == Scope.UNCHANGED:
    EnvironmentalScore = roundup(roundup(min(ModifiedImpact + ModifiedExploitability, 10)) * 
                            Metric[ExploitCodeMaturity] * 
                            Metric[RemediationLevel] *
                            Metric[ReportConfidence])
elif ModifiedScope == Scope.CHANGED:
    EnvironmentalScore = roundup(roundup(min(1.08 * (ModifiedImpact + ModifiedExploitability), 10)) *
                               Metric[ExploitCodeMaturity] * Metric[RemediationLevel] * 
                               Metric[ReportConfidence])

print(f"Base Score: {BaseScore}")
print(f"Temporal Score: {TemporalScore}")
print(f"Environmental Score: {EnvironmentalScore}")
