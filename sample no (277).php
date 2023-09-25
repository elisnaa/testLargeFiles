<!--
# Sample information

Patterns:
- Source: _COOKIE ==> Filters:[]
- Sanitization: fnmatch_prm__<s>(*)_<i>(0) ==> Filters:[]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: xss_javascript
- Sink: echo_func

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Escape quotes with "
2. The ; can be used to chain commands
-->
<?php
# Init

# Sample
$tainted = $_COOKIE;
$tainted = $tainted["t"];
if(fnmatch("*", $tainted, 0))
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $pre = "<script>alert(\"Hello";
  $post = "\");</script>";
  $context = ($pre . ($dataflow . $post));
  echo($context);
}

?>