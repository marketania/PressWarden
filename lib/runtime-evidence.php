<?php
/** Read-only bounded configuration evidence; PHP 7.4. Never evaluates config. */
$error=0;$count=0;$pending='';
while(!feof(STDIN)){
 $chunk=fread(STDIN,8192);if($chunk===false){$error=1;break;}$pending.=$chunk;
 if(strlen($pending)>32768&&strpos($pending,"\0")===false){$error=1;break;}
 while(($pos=strpos($pending,"\0"))!==false){$path=substr($pending,0,$pos);$pending=substr($pending,$pos+1);
  if(++$count>20000){$error=1;break 2;}
  $st=@lstat($path);if(!$st||is_link($path)||($st['mode']&0170000)!==0100000||$st['size']>1048576){$error=1;continue;}
  $h=@fopen($path,'rb');if(!$h){$error=1;continue;}$i=0;$total=0;
  while(($line=fgets($h,65538))!==false){$i++;$total+=strlen($line);if(strlen($line)>65536||$total>1048576){$error=1;break;}
   if(preg_match('/^\s*(?:php_(?:admin_)?(?:value|flag)\s+)?(auto_prepend_file|auto_append_file|allow_url_include)\s*(?:=|\s)\s*([^;#\r\n]+)/i',$line,$m)){
    $v=trim($m[2]," \t\"'");if($v===''||in_array(strtolower($v),['none','off','0','false'],true))continue;
    $name=preg_replace('/[\x00-\x1f\x7f]/','?', $path);
    // Deliberately do not print directive values: URLs may contain credentials.
    echo $name,':',$i,': ',strtolower($m[1]),' configured; inspect source locally (value withheld)',"\n";
   }
  }
  if(!feof($h))$error=1;fclose($h);
 }
}
if($pending!=='')$error=1;
exit($error?2:0);
