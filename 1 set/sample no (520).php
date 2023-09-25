<!--
# Sample information

Patterns:
- Source: _POST ==> Filters:[]
- Sanitization: gettype_check_prm__<s>(string) ==> Filters:[]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: xss_quotes
- Sink: user_error_prm_

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Create script tag with <script>
2. Quotes are useless inside plain html context for XSS
-->
<?php
# Init

# Sample
$tainted = $_POST;
$tainted = $tainted["t"];
if(gettype($tainted) == "string")
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $context = (("Hello to \"" . $dataflow) . "\"");
  user_error($context);
}

?>