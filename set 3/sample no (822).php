<!--
# Sample information

Patterns:
- Source: _REQUEST ==> Filters:[]
- Sanitization: strstr_prm__<s>(1) ==> Filters:[]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: xss_plain
- Sink: printf_func_prm__<s>(Print this: %s)

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Create script tag with <script>
-->
<?php
# Init

# Sample
$tainted = $_REQUEST;
$tainted = $tainted["t"];
$sanitized = strstr($tainted, "1");
$dataflow = $sanitized;
$context = ("Hello" . $dataflow);
printf("Print this: %s", $context);

?>