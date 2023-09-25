<!--
# Sample information

Patterns:
- Source: _COOKIE ==> Filters:[]
- Sanitization: addcslashes_prm__<s>(;:'") ==> Filters:[][Note: Escapes characters with \ but can be bypassed because \ is not escaped. E.g. \" to bypass the escaping of ".]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: xss_html_param
- Sink: user_error_prm_

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Escape quotes with "
2. It is possible to create javascript parameters for: img attributes: onerror
-->
<?php
# Init

# Sample
$tainted = $_COOKIE;
$tainted = $tainted["t"];
$sanitized = addcslashes($tainted, ";:'\"");
$dataflow = $sanitized;
$context = (("<img src=\"" . $dataflow) . "\"/>");
user_error($context);

?>