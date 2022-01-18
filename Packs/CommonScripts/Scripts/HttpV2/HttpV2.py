import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, List
import json
import xml.etree.ElementTree as ET

CONTENT_TYPE_MAPPER = {
    "json": "application/json",
    "xml": "text/xml",
    "form": "application/x-www-form-urlencoded",
    "data": "multipart/form-data"
}


class Client(BaseClient):
    def __init__(self, base_url: str, auth: tuple, verify: bool, proxy: bool):

        super().__init__(base_url=base_url, auth=auth, verify=verify, proxy=proxy)

    def http_request(self, method: str, full_url: str = '', headers=None, resp_type='response', params=None,
                     data=None, timeout=10, retries=0, status_list_to_retry=None, raise_on_status=False,
                     allow_redirects=False):
        try:
            res = self._http_request(
                method=method,
                full_url=full_url,
                headers=headers,
                params=params,
                timeout=timeout,
                resp_type=resp_type,
                status_list_to_retry=status_list_to_retry,
                raise_on_status=raise_on_status,
                retries=retries,
                data=data,
                error_handler=self._generic_error_handler,
                allow_redirects=allow_redirects
            )
        except requests.exceptions.ConnectTimeout as exception:
            err_msg = 'Connection Timeout Error - potential reasons might be that the Server URL parameter' \
                      ' is incorrect or that the Server is not accessible from your host.'
            raise DemistoException(err_msg, exception)
        return res

    @staticmethod
    def _generic_error_handler(res):
        status_code = res.status_code
        if status_code == 400:
            raise DemistoException(f"Bad request. Status code: {status_code}. Origin response from server: {res.text}")

        if status_code == 401:
            raise DemistoException(f"Unauthorized. Status code: {status_code}. Origin response from server: {res.text}")

        if status_code == 403:
            raise DemistoException(f"Invalid permissions. Status code: {status_code}. "
                                   f"Origin response from server: {res.text}")

        if status_code == 404:
            raise DemistoException(f"The server has not found anything matching the request URI. Status code:"
                                   f" {status_code}. Origin response from server: {res.text}")
        if status_code == 500:
            raise DemistoException(f"Internal server error. Status code: {status_code}."
                                   f" Origin response from server: {res.text}")

        if status_code == 502:
            raise DemistoException(f"Bad gateway. Status code: {status_code}. Origin response from server: {res.text}")


def create_headers(headers: Dict, request_content_type_header: str, response_content_type_header: str) \
        -> Dict[str, str]:
    if request_content_type_header in CONTENT_TYPE_MAPPER.keys():
        request_content_type_header = CONTENT_TYPE_MAPPER[request_content_type_header]
    if response_content_type_header in CONTENT_TYPE_MAPPER.keys():
        response_content_type_header = CONTENT_TYPE_MAPPER[response_content_type_header]
    if request_content_type_header and not headers.get('Content-Type'):
        headers['Content-Type'] = request_content_type_header
    if response_content_type_header and not headers.get('Accept'):
        headers['Accept'] = response_content_type_header

    return headers


def save_res_to_file(res: str, file_name: str):
    return return_results(fileResult(file_name, res))


def str_parsed_response(res: str, parse_response_as: str) -> str:
    if parse_response_as == 'json':
        res = json.dumps(res)
    else:
        res = str(res)
    return res


def get_parsed_response(res, parse_response_as) -> Dict:
    if parse_response_as == 'json':
        parsed_res = res
    else:
        parsed_res = str(res)
    return {'Results': parsed_res}


def get_status_list(status_list: List) -> List[int]:
    final_status_list = []
    for status in status_list:
        range_numbers = status.split('-')
        if len(range_numbers) == 1:
            final_status_list.append(int(range_numbers[0]))
        else:
            status_range = list(range(int(range_numbers[0]), int(range_numbers[1]) + 1))
            final_status_list.extend(status_range)
    return final_status_list


''' MAIN FUNCTION '''


def main(args: Dict):
    method = args.get('method', '')
    full_url = args.get('url', '')
    body = args.get('body', '')
    request_content_type = args.get('request_content_type', '')
    response_content_type = args.get('response_content_type', '')
    parse_response_as = args.get('parse_response_as', 'raw_response')
    params = args.get('params', {})
    headers = args.get('headers', {})
    headers = create_headers(headers, request_content_type, response_content_type)
    auth = tuple(argToList(args.get('basic_auth', None)))
    save_as_file = args.get('save_as_file', 'no')
    file_name = args.get('filename', 'http-file')
    enable_redirect = argToBoolean(args.get('enable_redirect', True))
    timeout = arg_to_number(args.get('timeout', 10))
    retry_on_status = args.get('retry_on_status', None)
    raise_on_status = True if retry_on_status else False
    retry_status_list = get_status_list(argToList(retry_on_status))
    retry_count = arg_to_number(args.get('retry_count', 3))
    proxy = argToBoolean(args.get('proxy', False))
    verify = argToBoolean(not args.get('unsecure', False))

    client = Client(base_url=full_url, auth=auth, verify=verify, proxy=proxy)
    kwargs = {
        'method': method,
        'full_url': full_url,
        'headers': headers,
        'data': body,
        'timeout': timeout,
        'params': params,
        'resp_type': parse_response_as
    }
    if raise_on_status:
        kwargs.update({
            'retries': retry_count,
            'status_list_to_retry': retry_status_list,
            'raise_on_status': raise_on_status
        })
    if not enable_redirect:
        kwargs.update({
            'allow_redirects': enable_redirect
        })

    res = client.http_request(**kwargs)
    str_parsed_res = str_parsed_response(res, parse_response_as)
    dict_parsed_res = get_parsed_response(res, parse_response_as)

    if save_as_file == 'yes':
        save_res_to_file(str_parsed_res, file_name)

    return CommandResults(
        readable_output=f"Sent a {method} request to {full_url}",
        outputs_prefix='HttpV2',
        outputs=dict_parsed_res,
        raw_response=dict_parsed_res
    )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main(demisto.args()))
    except Exception as exc:
        return_error(str(exc), error=exc)
