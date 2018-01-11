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

    code = str(code)

    if not response.output_status.startswith(code.encode()):
        msg = 'Response status was %s, not %s.' % (response.output_status,
                                                   code)

        if hasattr(response, 'json'):
            msg += ' Response body was:\n%s' % json.dumps(
                response.json, sort_keys=True, indent=4,
                separators=(',', ': '))
        else:
            msg += 'Response body was:\n%s' % getResponseBody(response)

        assert response.output_status.startswith(code.encode()), msg


def assertStatusOk(response):
    __tracebackhide__ = True
    return assertStatus(response, 200)


def assertMissingParameter(response, param):
    """
    Assert that the response was a "parameter missing" error response.

    :param response: The response object.
    :param param: The name of the missing parameter.
    :type param: str
    """
    __tracebackhide__ = True
    assert response.json.get('message', '') == 'Parameter "%s" is required.' % param
    assertStatus(response, 400)


def assertRequiredParams(server, path='/', method='GET', required=(), user=None):
    """
    Ensure that a set of parameters is required by the endpoint.
    :param path: The endpoint path to test.
    :param method: The HTTP method of the endpoint.
    :param required: The required parameter set.
    :type required: sequence of str
    """
    __tracebackhide__ = True
    for exclude in required:
        params = dict.fromkeys([p for p in required if p != exclude], '')
        resp = server.request(path=path, method=method, params=params, user=user)
        assertMissingParameter(resp, exclude)
