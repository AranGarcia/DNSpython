from enum import Enum

OP_CODE = ["Standard query", "Deprecated",
           "Deprecated", "Deprecated", "Notify", "Update"]
# The meaning of the RCODE, mapping it's value to the indexes in the array
# Values 0-5 from [RFC 1035], which are for Query/Responses
# Values 6-10 from [RFC 2136], which are for Updates

R_CODE = ["NoError", "FormErr", "ServFail", "NXDomain", "NotImp",
          "Refused", "YXDomain", "YXRRSet", "NXRRSet", "NotAuth", "NotZone "]


class RCODE(Enum):
    NoError = 0,    # No error
    FormErr = 1,    # Format error
    ServFail = 2,   # Server failure
    NXDomain = 3,   # Non existent domain
    NotImp = 4,     # Request not supported
    Refused = 5,    # Server unwilling to provide answer
    YXDomain = 6,   # Name exists but shouldn't be used (Updates)
    YXRRSet = 7,    # RRSet exists but shouldn't        (Updates)
    NXRRSet = 8,    # RRSet doesn't exist but should    (Updates)
    NotAuth = 9,    # Server not authorized for zone    (Updates)
    NotZone = 10,   # Name not contained in zone        (Updates)


class RRType(Enum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    NAPTR = 35
    OPT = 41
    IXFR = 251
    AXFR = 252
    ANY = 255


class RRClass(Enum):
    IN = 1
    NONE = 254
    ANY = 255
