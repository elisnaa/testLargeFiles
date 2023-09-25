<!--
# Sample information

Patterns:
- Source: apache_request_headers ==> Filters:[]
- Sanitization: json_encode_prm__<c>(JSON_PRETTY_PRINT)_<i>(512) ==> Filters:[Filtered(&), Escape[\](\)]
- Filters complete: Filters:[Filtered(&), Escape[\](\)]
- Dataflow: assignment
- Context: xss_html_param
- Sink: trigger_error_prm__<c>(E_USER_ERROR)

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Escape quotes with "
2. Escape quotes with "
3. It is possible to create javascript parameters for: img attributes: onerror
-->
<?php
# Init

# Sample
$tainted = apache_request_headers();
$sanitized = json_encode($tainted, JSON_PRETTY_PRINT, 512);
$dataflow = $sanitized;
$context = (("<img src=\"" . $dataflow) . "\"/>");
trigger_error($context, E_USER_ERROR);

?>