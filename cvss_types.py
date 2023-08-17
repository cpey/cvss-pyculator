from enum import Enum

class Vector(Enum):
    NETWORK = 1
    ADJACENT = 2
    LOCAL = 3
    PHYSICAL = 4
    ND = 127

class Complexity(Enum):
    LOW = 1
    HIGH = 2
    ND = 127

class Privileges(Enum):
    NONE = 1
    LOW = 2
    HIGH = 3
    CH_LOW = 125   # If Scope / Modified Scope is Changed
    CH_HIGH = 126  # If Scope / Modified Scope is Changed
    ND = 127

class Interaction(Enum):
    NONE = 1
    REQUIRED = 2
    ND = 127

class Scope(Enum):
    CHANGED = 1
    UNCHANGED = 2
    ND = 127

class CIA(Enum):
    NONE = 1
    LOW = 2
    HIGH = 3
    ND = 127

class Maturity(Enum):
    UNPROVEN = 1
    POC = 2
    FUNCTIONAL = 3
    HIGH = 4
    ND = 127

class Remediation(Enum):
    OFFICIAL = 1
    TEMPORARY = 2
    WORKAROUND = 3
    UNAVAILABLE = 4
    ND = 127

class Confidence(Enum):
    UNKNOWN = 1
    REASONABLE = 2
    CONFIRMED = 3
    ND = 127

class CIAR(Enum):
    LOW = 1
    MED = 2
    HIGH = 3
    ND = 127

