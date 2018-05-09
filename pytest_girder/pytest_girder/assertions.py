import json

from .utils import getResponseBody


def assertStatus(response, code):
    """
    Call this to assert that a given HTTP status code was returned.

    :param response: The response object.
    :param code: The status code.
    :type code: int or str
    """
    # Hide tracebacks for this function within pytest
    __tracebackhide__ = True

    if response.status_code != code:
        msg = 'Response status was %s, not %s.' % (response.status, code)

        if response.headers['Content-Type'] == 'application/json':
            msg += ' Response body was:\n%s' % json.dumps(
                response.data, sort_keys=True, indent=4,
                separators=(',', ': '))
        else:
            msg += 'Response body was:\n%s' % getResponseBody(response)

        assert response.status_code == code, msg


def assertStatusOk(response):
    __tracebackhide__ = True
    return assertStatus(response, 200)
