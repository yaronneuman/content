Sends http request

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| url | Specify where the request should be sent. Include the URI scheme \('http' or 'https'\). |
| method | Specify the HTTP method to use. |
| headers | Specify a hash of headers to send with the request. |
| body | Specify the body of the request. |
| request_content_type | Specify the content type to use with the request. For example: application/json.<br/>Mapped types are:<br/>json  \(application/json\)<br/>xml \(text/xml\)<br/>form \(application/x-www-form-urlencoded\)<br/>data \(multipart/form-data\) |
| response_content_type | Choose how responses are converted into event data. For example: application/json.<br/>Mapped types are:<br/>json  \(application/json\)<br/>xml \(text/xml\)<br/>form \(application/x-www-form-urlencoded\)<br/>data \(multipart/form-data\) |
| parse_response_as | Specify how you would like to parse the response. |
| basic_auth | The request authorization, for example: \(username, password\) |
| params | URL parameters to specify the query. |
| timeout | Specify the timeout of the HTTP request in seconds. Defaults to 10 seconds. |
| enable_redirect | The request will be called again with the new URL. |
| retry_on_status |  Specify the array of status codes that should cause a retry.  |
| retry_count | How many retries should be made in case of a failure. |
| save_as_file | Save the response in a file. |
| filename | filename |
| unsecure | Trust any certificate \(not secure\) |
| proxy | Use system proxy settings |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| HttpV2 | The response  of the Http request. | String |


## Script Examples
### Example command
```!HttpV2 method=GET url="https://test.jamfcloud.com/JSSResource/computers/id/1/subset/General" response_content_type=json request_content_type=json basic_auth=panwdemisto,Gr2VrDEBTGUVkjwF! parse_response_as=json```

### Context Example
```json
{
    "HttpV2": {
        "Results": {
            "computer": {
                "general": {
                    "alt_mac_address": "A1:34:95:EC:97:C4",
                    "alt_network_adapter_type": "",
                    "asset_tag": "",
                    "barcode_1": "",
                    "barcode_2": "",
                    "distribution_point": "",
                    "id": 1,
                    "initial_entry_date": "2021-03-29",
                    "initial_entry_date_epoch": 1617021852322,
                    "initial_entry_date_utc": "2021-03-29T12:44:12.322+0000",
                    "ip_address": "111.243.192.20",
                    "itunes_store_account_is_active": false,
                    "jamf_version": "9.6.29507.c",
                    "last_cloud_backup_date_epoch": 0,
                    "last_cloud_backup_date_utc": "",
                    "last_contact_time": "2014-10-24 10:26:55",
                    "last_contact_time_epoch": 1414146415335,
                    "last_contact_time_utc": "2014-10-24T10:26:55.335+0000",
                    "last_enrolled_date_epoch": 1414146339607,
                    "last_enrolled_date_utc": "2014-10-24T10:25:39.607+0000",
                    "last_reported_ip": "192.168.1.10",
                    "mac_address": "11:5B:35:CA:12:56",
                    "mdm_capable": false,
                    "mdm_capable_users": {},
                    "mdm_profile_expiration_epoch": 0,
                    "mdm_profile_expiration_utc": "",
                    "name": "Computer 1",
                    "network_adapter_type": "",
                    "platform": "Mac",
                    "remote_management": {
                        "managed": false,
                        "management_password_sha256": "abc0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "management_username": ""
                    },
                    "report_date": "2021-03-29 12:44:12",
                    "report_date_epoch": 1617021852595,
                    "report_date_utc": "2021-03-29T12:44:12.595+0000",
                    "serial_number": "AA40F81C60A3",
                    "site": {
                        "id": -1,
                        "name": "None"
                    },
                    "supervised": false,
                    "sus": "",
                    "udid": "AA40F812-60A3-11E4-90B8-12DF261F2C7E"
                }
            }
        }
    }
}
```

### Human Readable Output

>Sent a GET request to https://test.jamfcloud.com/JSSResource/computers/id/1/subset/General
