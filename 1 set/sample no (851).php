<!--
# Sample information

Patterns:
- Source: _REQUEST ==> Filters:[]
- Sanitization: settype_prm__<s>(string) ==> Filters:[]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: sql_apostrophe
- Sink: db2_prepare_prm__<$>(db)

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Escape the apostrophe with '
2. No enclosure and special chars are allowed -> SQL injection
-->
<?php
# Init
$dsn = "DATABASE=myDB;HOSTNAME=ibm_db2;PORT=50000;PROTOCOL=TCPIP;UID=db2inst1;PWD=ibm_db2_pw;";
$db = db2_connect($dsn, "", "");


# Sample
$tainted = $_REQUEST;
$tainted = $tainted["t"];
if(settype($tainted, "string"))
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $context = (("SELECT * FROM users WHERE password ='" . $dataflow) . "';");
  $stmt = db2_prepare($db, $context);
  if($stmt == false)
  {
    die(db2_stmt_errormsg());
  }
  $result = db2_execute($stmt, []);
  while(($row = db2_fetch_array($stmt)))
  {
    echo(htmlentities(print_r($row, true)));
  }
}

?>