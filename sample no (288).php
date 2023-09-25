<!--
# Sample information

Patterns:
- Source: _GET ==> Filters:[]
- Sanitization: sscanf_prm__<s>(foo %s) ==> Filters:[]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: xss_javascript_no_enclosure
- Sink: trigger_error_prm__<c>(E_USER_ERROR)

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. The ; can be used to chain commands
-->
<?php
# Init

# Sample
$tainted = $_GET;
$tainted = $tainted["t"];
$sanitized = sscanf($tainted, "foo %s");
$sanitized = implode($sanitized, "_");
$dataflow = $sanitized;
$pre = "<script>alert(Hello";
$post = ");</script>";
$context = ($pre . ($dataflow . $post));
trigger_error($context, E_USER_ERROR);

?>