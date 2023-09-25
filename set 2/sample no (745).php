<!--
# Sample information

Patterns:
- Source: getallheaders ==> Filters:[]
- Sanitization: preg_replace_prm__<s>(_'_)_<s>() ==> Filters:[Filtered(')]
- Filters complete: Filters:[Filtered(')]
- Dataflow: assignment
- Context: xss_html_param_a
- Sink: print_func

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. It is possible to create a javascript context with: javascript:alert(1)
-->
<?php
# Init

# Sample
$tainted = getallheaders();
$tainted = $tainted["t"];
$sanitized = preg_replace("/'/", "", $tainted);
$dataflow = $sanitized;
$context = (("<a href=\"" . $dataflow) . "\">link</a>");
print($context);

?>