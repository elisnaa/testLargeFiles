<!--
# Sample information

Patterns:
- Source: apache_request_headers ==> Filters:[]
- Sanitization: cast_prm__TYPE_STRING ==> Filters:[]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: xss_apostrophe
- Sink: trigger_error_prm__<c>(E_USER_ERROR)

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Create script tag with <script>
2. Apostrophe are useless inside plain html context for XSS
-->
<?php
# Init

# Sample
$tainted = apache_request_headers();
$tainted = $tainted["t"];
$sanitized = (string)($tainted);
$dataflow = $sanitized;
$context = (("Hello to '" . $dataflow) . "'");
trigger_error($context, E_USER_ERROR);

?>