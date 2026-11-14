class CoseIllegalAlgorithm(Exception):
    pass


class CoseUnsupportedCurve(Exception):
    pass


class CoseIllegalKeyOps(Exception):
    pass


class CoseIllegalKeyType(Exception):
    pass


class CoseMalformedMessage(Exception):
    pass


class CoseInvalidKey(Exception):
    pass


class CoseException(Exception):
    pass


class CoseInvalidParameter(CoseException, ValueError):
    pass


class CoseInvalidTag(CoseException):
    pass
