<!--
# Sample information

Patterns:
- Source: _GET ==> Filters:[]
- Sanitization: filter_var_prm__<c>(FILTER_UNSAFE_RAW) ==> Filters:[]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: xss_apostrophe
- Sink: user_error_prm_

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
$tainted = $_GET;
$tainted = $tainted["t"];
$sanitized = filter_var($tainted, FILTER_UNSAFE_RAW);
$dataflow = $sanitized;
$context = (("Hello to '" . $dataflow) . "'");
user_error($context);

?>