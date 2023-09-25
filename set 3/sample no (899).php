<!--
# Sample information

Patterns:
- Source: _POST ==> Filters:[]
- Sanitization: json_encode_prm__<c>(ENT_COMPAT) ==> Filters:[Filtered(&), Escape[\](", \)]
- Filters complete: Filters:[Filtered(&), Escape[\](", \)]
- Dataflow: assignment
- Context: xss_quotes
- Sink: echo_func

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Escape quotes with "
2. Create script tag with <script>
3. Quotes are useless inside plain html context for XSS
-->
<?php
# Init

# Sample
$tainted = $_POST;
$sanitized = json_encode($tainted, ENT_COMPAT);
$dataflow = $sanitized;
$context = (("Hello to \"" . $dataflow) . "\"");
echo($context);

?>