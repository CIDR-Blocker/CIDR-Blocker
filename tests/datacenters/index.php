<?php

function ip2cidr($ips)
{
    $return = array();
    $num = ip2long($ips[1]) - ip2long($ips[0]) + 1;
    $bin = decbin($num);
 
    $chunk = str_split($bin);
    $chunk = array_reverse($chunk);
    $start = 0;
 
    while ($start < count($chunk))
    {
        if ($chunk[$start] != 0)
        {
            $start_ip = isset($range) ? long2ip(ip2long($range[1]) + 1) : $ips[0];
            $range = cidr2ip($start_ip . '/' . (32 - $start));
            $return[] = $start_ip . '/' . (32 - $start);
        }
        $start++;
    }
    return $return;
}

function cidr2ip($cidr)
{
    $ip_arr = explode('/', $cidr);
    $start = ip2long($ip_arr[0]);
    $nm = $ip_arr[1];
    $num = pow(2, 32 - $nm);
    $end = $start + $num - 1;
    return array($ip_arr[0], long2ip($end));
}


function valid_ip_cidr($cidr, $must_cidr = false)
{
    if (!preg_match("/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(\/[0-9]{1,2})?$/", $cidr))
    {
        $return = false;
    } else
    {
        $return = true;
    }
    if ($return == true)
    {
        $parts = explode("/", $cidr);
        $ip = $parts[0];
        $netmask = $parts[1];
        $octets = explode(".", $ip);
        foreach ($octets as $octet)
        {
            if ($octet > 255)
            {
                $return = false;
            }
        }
        if ((($netmask != "") && ($netmask > 32) && !$must_cidr) || (($netmask == ""||$netmask > 32) && $must_cidr))
        {
            $return = false;
        }
    }
    return $return;
}

$lines = file('datacenters.csv');

$out = fopen('output.csv', 'w');

foreach ($lines as $line) {
    $parts = explode(',', $line);
	
	$cidrs = ip2cidr(array($parts['0'], $parts['1']));
	
	foreach ($cidrs as $cidr) {
		if (valid_ip_cidr($cidr, true))
			fwrite($out, '"' . $cidr . '","' . $parts['2'] . '"' . "\r\n");
	}
}

fclose($out);

 ?>
