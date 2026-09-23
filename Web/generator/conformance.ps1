#Requires -Version 7.2
#PowerShell behaviour the browser runtime reproduces. Test-WebParity.ps1 runs this file in PowerShell and, converted, on the
#runtime, and requires identical output. Left out on purpose: the current culture (the runtime formats like the invariant
#culture), [int] versus [long] versus [double] (JavaScript has one number type), [char], '\' as path separator, and the
#enumeration order of unordered hashtables (it differs per process in PowerShell itself; the runtime keeps insertion order).

function T($label, [scriptblock]$sb) { try { $r = & $sb; "$label => $r" } catch { "$label => THROW $($_.Exception.Message)" } }
function f1 { $null }; function f2 { }; function f3 { return $null }
T 'f1 count' { @(f1).Count }
T 'f2 count' { @(f2).Count }
T 'f3 count' { @(f3).Count }
T 'anull pipe' { $x = f2; @($x | % { 'hit' }).Count }
T 'null var pipe' { $x = $null; @($x | % { 'hit' }).Count }
T 'anull in @()' { $x = f2; @($x).Count }
T 'f1 assigned pipe' { $x = f1; @($x | % { 'hit' }).Count }
T 'sort nulls' { (@(3,$null,1) | Sort-Object | % { if ($null -eq $_) {'N'} else {$_} }) -join ',' }
T 'sort desc nulls' { (@(3,$null,1) | Sort-Object -Descending | % { if ($null -eq $_) {'N'} else {$_} }) -join ',' }
T 'sort strings' { (('b','A','a','B','-a','_b','a-b','ab','AZ-STG-10','AZ-STG-9','Z','e', 'a b', 'a.b', 'a_b', 'aB', 'Ab') | Sort-Object) -join ',' }
T 'sort unique' { (('a','A','b') | Sort-Object -Unique) -join ',' }
T 'sort mixed' { (@(10,'9',2) | Sort-Object) -join ',' }
T 'sort bools' { (@($true,$false,$true) | Sort-Object) -join ',' }
T 'group order' { ('b','a','B','c' | Group-Object | % { "$($_.Name):$($_.Count)" }) -join ',' }
T 'memenum 0' { $r = @().n; "[$r] $($null -eq $r)" }
T 'memenum mixed' { $r = @([pscustomobject]@{n=1},[pscustomobject]@{m=2}).n; "$($r.GetType().Name) $(@($r).Count)" }
T 'memenum nested arrays' { $r = @([pscustomobject]@{n=@(1,2)},[pscustomobject]@{n=@(3)}).n; "$(@($r).Count)" }
T 'memenum nulls' { $r = @([pscustomobject]@{n=$null},[pscustomobject]@{n=$null}).n; "$(@($r).Count)" }
T 'ht count key' { $ht = @{count=5}; $ht.Count }
T 'ht keys' { $ht = @{keys='x'}; $ht.Keys }
T 'int round' { "$([int]2.5) $([int]3.5) $([int]'4') $([int]-2.5) $([int]'')" }
T 'math round' { "$([math]::Round(2.45,1)) $([math]::Round(0.125,2)) $([math]::Round(2.5)) $([math]::Round(66.66666,1)) $([math]::Round(1.005,2))" }
T 'num strings' { "$(1.0)|$(0.1+0.2)|$(1e21)|$(1e-7)|$([double]5)|$(1/3)|$(123456789012)|$(1e15)|$(1e16)|$(-0.0)" }
T 'eq' { "$('1' -eq 1) $(1 -eq '1') $($null -eq 0) $(0 -eq $null) $('abc' -eq 'ABC') $($true -eq 'false') $('true' -eq $true) $(1 -eq '1.0') $('' -eq $null) $($false -eq 0) $(0 -eq $false) $('False' -eq $false) $($false -eq 'False')" }
T 'eq array' { (@(1,2,3,2) -eq 2).Count }
T 'ne null' { (@(1,$null,2) -ne $null).Count }
T 'truthy' { "$([bool]@(0)) $([bool]@($false)) $([bool]'False') $([bool]'0') $([bool]@(0,0)) $([bool]@()) $([bool]0.0) $([bool]@($null)) $([bool]@(@())) $([bool]([pscustomobject]@{}))" }
T 'in' { "$('A' -in 'a','b') $('a' -in @()) $($null -in @($null)) $(1 -in '1','2') $(@('a') -contains 'A') $('ab' -in 'a','b')" }
T 'plus' { "$('a' + 1)|$(1 + '2')|$((@(1) + 2).Count)|$($null + 1)|$($null + 'a')|$((@($null) + @(1)).Count)|$(($null + @(1)).Count)|$(1 + 2.5)|$('5' * 2)" }
T 'split' { "$(('a,b,,c' -split ',').Count) $(('a1b22c' -split '\d+') -join '|')" }
T 'dotsplit' { ('a//b/'.Split('/')).Count }
T 'like' { "$('abc' -like 'A*') $('a[b' -like 'a`[b') $('dataMaskingPolicies/Default' -like 'dataMaskingPolicies*') $('x' -like '[xy]')" }
T 'replace' { "$('abc123' -replace '(\d+)', '<$1>') $('ABC' -replace 'b','x') $('a.b' -replace '\.', '$0$0')" }
T 'index' { $a = 1,2,3; "$($null -eq $a[5]) $($a[-1]) $($a[1..5] -join ',') $('abc'[0]) $((5)[0]) $($null -eq @(1,2,3)[-5])" }
T 'ht pipe' { @{a=1} | % { $_.GetType().Name } }
T 'pco order' { ([pscustomobject]@{b=1;a=2;c=3}).PSObject.Properties.Name -join ',' }
T 'ht case' { $x = @{}; $x['A'] = 1; "$($x['a']) $($x.a) $($x.ContainsKey('a'))" }
T 'json parse' { $o = ConvertFrom-Json '{"a":[1],"B":2,"5":"five","1.1":"x"}'; "$($o.a.Count) $($o.b) $(@($o.PSObject.Properties.Name) -join ',')" }
T 'json empty arr' { $o = '[]' | ConvertFrom-Json; "$($null -eq $o) $(@($o).Count)" }
T 'json noenum' { $o = ConvertFrom-Json '[1]' -NoEnumerate; "$($o.GetType().Name) $($o.Count)" }
T 'expand arr' { $x = 'a','b'; "$x|$true|$null|$(@())|$(@($null,1))" }
T 'string cast' { "[$([string]$null)] [$([string]@(1,2))] [$([string]$true)] [$([string]1.50)]" }
T 'join null' { "[$($null -join ',')] [$(@($null,'a') -join ',')]" }
T 'where scalar' { @(5 | ? { $_ -gt 1 }).Count }
T 'select first empty' { $r = @() | Select-Object -First 1; "$($null -eq $r)" }
T 'ordered' { $o = [ordered]@{b=1;a=2}; "$($o.Keys -join ',') $($o.Values -join ',') $($null -eq $o['x']) $($o.Contains('B')) $($o.Count)" }
T 'measure' { "$((3,1.5,2 | Measure-Object -Maximum).Maximum) $((3,1.5,2 | Measure-Object -Minimum).Minimum)" }
T 'lt strings' { "$('a' -lt 'B') $('B' -lt 'a') $('a' -lt 'a-') $('10' -lt '9') $(10 -lt '9')" }
T 'null member' { $x = $null; "$($null -eq $x.foo.bar) $($x.Count) $(@{a=1}.Count) $(([pscustomobject]@{a=1}).Count) $('abc'.Count) $('abc'.Length)" }
T 'list null' { $l = [System.Collections.Generic.List[object]]::new(); $l.Add($null); "$($l.Count) $(@($l).Count)" }
T 'version cmp' { "$([version]'1.2' -ge [version]'1.10') $([version]'1.2' -lt [version]'1.10')" }
T 'ht incr' { $h=@{}; $h['x']++; $h.y += 1; "$($h['x']) $($h.y)" }
T 'multi assign' { $a, $b, $c = 1,2,3,4; $s1 = "$a|$b|$($c -join ',')"; $a, $b = @(1); "$s1 ; $a|$($null -eq $b)" }
T 'switch' { $r = switch ('b') { 'a' { 1 } 'B' { 2 } default { 3 } }; $r }
T 'switch arr' { $r = switch (@('a','b','z')) { 'a' { 1 } 'b' { 2 } default { 9 } }; $r -join ',' }
T 'return comma' { function g { return , @(1) }; $r = g; "$($r.GetType().Name) $(@(g).Count)" }
T 'dates' { $d = [DateTimeOffset]::Parse('2026-01-02T03:04:05', [cultureinfo]::InvariantCulture).UtcDateTime; $d.ToString('o') }
T 'dates2' { $d = [DateTimeOffset]::Parse('2026-01-02', [cultureinfo]::InvariantCulture).UtcDateTime; $d.ToString('o') }
T 'date expand' { $d = [datetime]::new(2026,1,2,3,4,5,[DateTimeKind]::Utc); "$d" }
T 'hash plus' { $h = @{a=1} + @{b=2}; $h.Count }
T 'contains list' { $l = [System.Collections.Generic.List[string]]::new(); $l.Add('A'); "$($l.Contains('a')) $($l -contains 'a')" }
T 'hashset' { $s = [System.Collections.Generic.HashSet[string]]::new(); $null = $s.Add('A'); "$($s.Contains('a')) $($s.Add('A')) $($s.Count)" }
T 'match matches' { if ('abc' -match '(?<x>b)') { "$($Matches.x) $($Matches[0])" } }
T 'match array' { $r = @('ab','cd','ae') -match 'a'; "$($r -join ',')" }
T 'notmatch null' { "$($null -match 'a') $($null -notmatch 'a') $('' -match '^$')" }
T 'gt null' { "$(1 -gt $null) $($null -gt 1) $($null -lt 1) $(0 -gt $null)" }
T 'int string compare' { "$(2 -gt '10') $('2' -gt 10)" }
T 'pscustom from ordered' { $o = [pscustomobject][ordered]@{b=1;a=2}; $o.PSObject.Properties.Name -join ',' }
T 'negative idx range' { $a=1,2,3,4; ($a[-2..-1]) -join ',' }
T 'string eq array rhs' { 'a' -eq @('a') }
T 'foreach null' { $n = 0; foreach ($i in $null) { $n++ }; $n }
T 'foreach anull' { $n = 0; foreach ($i in (f2)) { $n++ }; $n }
T 'foreach scalar' { $n = 0; foreach ($i in 5) { $n++ }; $n }
T 'foreach ht' { $n = 0; foreach ($i in @{a=1;b=2}) { $n++ }; $n }
T 'sort by prop' { (@([pscustomobject]@{k='b'},[pscustomobject]@{k=$null},[pscustomobject]@{k='A'}) | Sort-Object k | % { "[$($_.k)]" }) -join '' }
T 'sort multi' { (@([pscustomobject]@{a=1;b='x'},[pscustomobject]@{a=1;b='a'},[pscustomobject]@{a=0;b='z'}) | Sort-Object a, b | % { $_.b }) -join '' }
T 'sort stable' { (@([pscustomobject]@{a=1;b='1'},[pscustomobject]@{a=1;b='2'},[pscustomobject]@{a=1;b='3'},[pscustomobject]@{a=0;b='0'},[pscustomobject]@{a=1;b='4'},[pscustomobject]@{a=1;b='5'}) | Sort-Object a | % { $_.b }) -join '' }
T 'measure empty' { $m = @() | Measure-Object -Maximum; "[$($m.Maximum)]" }
T 'string times' { "$('ab' * 3)" }
T 'bool plus' { $true + 1 }
T 'not string' { "$(-not 'a') $(-not '') $(-not @()) $(-not @(0))" }
T 'in ht keys' { $h = @{A=1}; 'a' -in $h.Keys }
T 'eq ordinal' { "$('é' -eq 'E') $('ß' -eq 'ss')" }
T 'dollar under nested' { (1..2 | % { $o = $_; (10..11 | % { $o * $_ }) -join '+' }) -join ';' }
T 'foreach-object assigns leak' { 1..3 | % { $leak = $_ }; $leak }
T 'where assign leak' { $null = 1..3 | ? { $w = $_; $true }; $w }
T 'function scope' { $v = 1; function h { $v = 2 }; h; $v }
T 'scriptblock scope' { $v = 1; & { $v = 2 }; $v }
T 'dot scope' { $v = 1; . { $v = 2 }; $v }
T 'dynamic read' { function outer { $dyn = 'seen'; inner }; function inner { $dyn }; outer }
T 'tostring fmt' { "$((0.5).ToString('0.#', [cultureinfo]::InvariantCulture)) $((12).ToString('0.#', [cultureinfo]::InvariantCulture)) $((73.25).ToString('0.#', [cultureinfo]::InvariantCulture)) $((73.25).ToString('0.0', [cultureinfo]::InvariantCulture)) $((0.05).ToString('0.#', [cultureinfo]::InvariantCulture)) $((0.25).ToString('0.#', [cultureinfo]::InvariantCulture)) $((0.35).ToString('0.#', [cultureinfo]::InvariantCulture))" }
T 'sort numeric strings' { (@('10','9','1') | Sort-Object) -join ',' }
T 'group many' { ('z','m','a','q','M','b' | Group-Object | % { "$($_.Name):$($_.Count)" }) -join ',' }
T 'group prop' { (@([pscustomobject]@{k='y'},[pscustomobject]@{k='x'},[pscustomobject]@{k=$null},[pscustomobject]@{k='Y'}) | Group-Object k | % { "[$($_.Name)]:$($_.Count)" }) -join ',' }
T 'group sb' { (@('B1','a1','b2') | Group-Object { $_.Substring(0,1).ToLowerInvariant() } | % { "$($_.Name):$($_.Group -join '+')" }) -join ',' }
T 'group nums' { (@(10,9,100) | Group-Object | % { $_.Name }) -join ',' }
T 'foreach member missing' { (@([pscustomobject]@{a=1}, [pscustomobject]@{b=2}) | % a | % { "[$_]" }) -join '' }
T 'foreach member null' { @(@([pscustomobject]@{a=$null}) | % a).Count }
T 'where eq syntax' { @(@([pscustomobject]@{s='Fail'},[pscustomobject]@{s='fail'},[pscustomobject]@{s='Pass'}) | Where-Object s -eq 'FAIL').Count }
T 'anull in ht' { $h = @{}; $h.k = (f2); "$($null -eq $h.k) $(@($h.k).Count) $(@($h.k | % { 1 }).Count)" }
T 'anull copy' { $x = f2; $y = $x; @($y | % { 1 }).Count }
T 'anull return' { function g { return (f2) }; @(g).Count }
T 'anull ordered' { $o = [ordered]@{ a = (f2) }; @($o.a | % { 1 }).Count }
T 'anull param' { function g($p) { @($p | % { 1 }).Count }; g (f2) }
T 'anull array literal' { $a = @((f2), 1); $a.Count }
T 'anull comma' { $a = (f2), 1; $a.Count }
T 'json fmt' { [ordered]@{a=@();b=@{};c=@(1,@(2,3));d=[ordered]@{e=$null;f='x"y'};g=$true} | ConvertTo-Json -Depth 5 }
T 'json single arr' { @(1) | ConvertTo-Json -Compress }
T 'json inputobject arr' { ConvertTo-Json -InputObject @(1) -Compress }
T 'json date' { [ordered]@{d=[datetime]::new(2026,1,2,3,4,5,[DateTimeKind]::Utc)} | ConvertTo-Json -Compress }
T 'json list' { $l = [System.Collections.Generic.List[string]]::new(); $l.Add('a'); [ordered]@{l=$l} | ConvertTo-Json -Compress }
T 'json hashset' { $s = [System.Collections.Generic.HashSet[string]]::new(); $null=$s.Add('a'); [ordered]@{s=$s} | ConvertTo-Json -Compress }
T 'csv' { ([pscustomobject]@{a='x,y';b=$null;c='q"t';d=1;e=$true} | ConvertTo-Csv -NoTypeInformation -UseQuotes AsNeeded) -join '|' }
T 'csv empty' { $r = @() | ConvertTo-Csv -NoTypeInformation -UseQuotes AsNeeded; "[$r]" }
T 'select first list' { $l = [System.Collections.Generic.List[object]]::new(); 1..5 | % { $l.Add($_) }; ($l | Select-Object -First 2) -join ',' }
T 'select skip' { (1..5 | Select-Object -Skip 3) -join ',' }
T 'sort unique nums' { (3,1,3,2 | Sort-Object -Unique) -join ',' }
T 'sort unique objs' { @(@([pscustomobject]@{a=1},[pscustomobject]@{a=1}) | Sort-Object -Unique).Count }
T 'regex matches' { $m = [regex]::Matches('a1b22', '\d+'); "$($m.Count) $($m[1].Value) $(@($m | % Value) -join ',')" }
T 'regex replace sb' { [regex]::Replace('a9b10', '\d+', { param($m) $m.Value.PadLeft(3,'0') }) }
T 'hashtable enum sort' { $h=[ordered]@{b=2;a=1}; ($h.GetEnumerator() | Sort-Object Key | % { "$($_.Key)=$($_.Value)" }) -join ',' }
T 'hashtable keys sort' { $h=@{b=2;a=1;C=3}; ($h.Keys | Sort-Object) -join ',' }
T 'string -replace null' { "[$($null -replace 'a','b')]" }
T 'split limit' { ('a@b@c'.Split('@', 2)) -join '|' }
T 'trim chars' { '/a/b/'.Trim('/') + '|' + '/a/'.TrimEnd('/') }
T 'tolower null' { $x = $null; try { $x.ToLowerInvariant() } catch { 'ERR:' + $_.Exception.Message } }
T 'index null' { $x = $null; try { $x[0] } catch { 'ERR:' + $_.Exception.Message } }
T 'prop on string' { 'abc'.foo -eq $null }
T 'method missing' { try { 'abc'.Nope() } catch { 'ERR:' + $_.Exception.Message } }
T 'pipe hashtable values' { $h=[ordered]@{a=1;b=2}; @($h.Values | % { $_ * 2 }) -join ',' }
T 'int division int' { $a = 10; $b = 4; "$($a / $b) $($a % $b)" }
T 'string compare -ge' { 'b' -ge 'B' }
T 'datetime compare' { $d1 = [datetime]::new(2026,1,1,0,0,0,[DateTimeKind]::Utc); $d2 = $d1.AddDays(1); "$($d2 -gt $d1) $(($d2 - $d1).TotalDays)" }
T 'timespan' { $t = [System.Xml.XmlConvert]::ToTimeSpan('P1DT2H'); "$($t.TotalHours) $($t.Days)" }
T 'switch regex' { $r = switch -Regex ('abc') { '^a' { 'A' } 'c$' { 'C' } }; $r -join ',' }
T 'switch wildcard' { $r = switch -Wildcard ('abc') { 'a*' { 'A' } default { 'D' } }; $r -join ',' }
T 'switch break' { $r = switch ('a') { 'a' { 'first'; break } 'a' { 'second' } }; $r -join ',' }
T 'switch dollar' { $r = switch (3) { { $_ -gt 2 } { 'big' } default { 'small' } }; $r }
T 'switch null' { $r = switch ($null) { $null { 'isnull' } default { 'd' } }; "$r" }
T 'bool param' { function g([bool]$b) { $b }; "$(g 1) $(g $true)" }
T 'string param null' { function g([string]$s) { $null -eq $s }; g $null }
T 'string param array' { function g([string]$s) { $s }; g @('a','b') }
T 'int param' { function g([int]$i) { $i }; "$(g '5') $(g $null) $(g 2.5)" }
T 'switch param' { function g([switch]$S) { [bool]$S }; "$(g) $(g -S) $(g -S:$false)" }
T 'string[] param' { function g([string[]]$s) { "$($s.Count) $($s.GetType().Name)" }; "$(g 'a') | $(g $null)" }
T 'hashtable arg' { function g { param([hashtable]$d) $d.Count }; g @{a=1} }
T 'args' { function g { param($a) "$a $($args -join ',')" }; g 1 2 3 }
T 'positional after named' { function g { param($a, $b) "$a-$b" }; g -b 2 1 }
T 'sb param positional' { $sb = { param($x, $y) "$x/$y" }; & $sb 1 2 }
T 'dollar underscore in function called in foreach' { function g { "[$_]" }; (1..2 | % { g }) -join '' }
T 'exception msg' { try { throw 'boom' } catch { $_.Exception.Message } }
T 'exception null method' { try { $n = $null; $n.Foo() } catch { $_.Exception.Message } }
T 'is types' { "$(@() -is [array]) $([ordered]@{} -is [System.Collections.IDictionary]) $(@{} -is [hashtable]) $('a' -is [System.Collections.IEnumerable]) $(@{} -is [System.Collections.IEnumerable]) $(([pscustomobject]@{}) -is [System.Management.Automation.PSCustomObject]) $((1) -is [System.Management.Automation.PSCustomObject])" }
T 'json obj is pscustom' { (ConvertFrom-Json '{"a":1}') -is [System.Management.Automation.PSCustomObject] }
T 'expand member of null prop' { $o = [pscustomobject]@{a=$null}; "[$($o.a.b)]" }
T 'uri escape' { [uri]::EscapeDataString("a b/c?d=é&'") }
T 'html encode' { [System.Net.WebUtility]::HtmlEncode("<a href='x'>&""é</a>") }
T 'padleft' { '7'.PadLeft(3, '0') }
T 'sort scriptblock multiple desc' { (@(1,3,2) | Sort-Object { - $_ }) -join ',' }
T 'where-object no match returns' { $r = @(1,2) | Where-Object { $_ -gt 5 }; "$($null -eq $r) $(@($r | % { 1 }).Count)" }
T 'foreach-object output nothing' { $r = @(1) | ForEach-Object { }; @($r | % { 1 }).Count }
T 'array plus anull' { $a = @(1) + (f2); $a.Count }
T 'expand hashtable' { "$(@{a=1})" }
T 'expand pscustom' { "$([pscustomobject]@{a=1;b='x'})" }
T 'string format -f' { '{0} {1}' -f 'a', $null }
T 'bool tostring' { $true.ToString().ToLowerInvariant() }
T 'contains op on string' { 'abc' -contains 'b' }
T 'ipaddress' { $ip = $null; $ok = [System.Net.IPAddress]::TryParse('10.1.2.3', [ref]$ip); "$ok $($ip.GetAddressBytes() -join '.') $($ip.AddressFamily)" }
T 'uint64 shift' { [uint64]10 -shl 24 }
T 'band' { ([uint64]4278190080 -band [uint64]4294967295) }
T 'version parse' { $v = $null; "$([version]::TryParse('1.2', [ref]$v)) $v $([version]::TryParse('abc', [ref]$v))" }
T 'unbound string' { function g([string]$s) { "[$($null -eq $s)|$s]" }; g }
T 'unbound int' { function g([int]$i) { "[$($null -eq $i)|$i]" }; g }
T 'unbound bool' { function g([bool]$b) { "[$($null -eq $b)|$b]" }; g }
T 'unbound switch' { function g([switch]$b) { "[$($null -eq $b)|$([bool]$b)]" }; g }
T 'unbound datetime' { function g([datetime]$d) { "[$($null -eq $d)]" }; g }
T 'unbound string[]' { function g([string[]]$s) { "[$($null -eq $s)]" }; g }
T 'unbound hashtable' { function g([hashtable]$h) { "[$($null -eq $h)]" }; g }
T 'unbound double' { function g([double]$d) { "[$($null -eq $d)|$d]" }; g }
T 'memenum none have' { $r = @('a','b').foo; "$($null -eq $r) $(@($r).Count)" }
T 'memenum pco none have' { $r = @([pscustomobject]@{a=1},[pscustomobject]@{a=2}).foo; "$($null -eq $r) $(@($r).Count)" }
T 'foreach member array value' { @(@([pscustomobject]@{a=@(1,2)}, [pscustomobject]@{a=@(3)}) | % a).Count }
T 'method enum' { @('a','b').ToUpper() -join ',' }
T 'ht add dup' { $h = @{}; $h.Add('a',1); $h.Add('A', 2) }
T 'adv unknown param' { function g { [CmdletBinding()] param($a) $a }; g -b 1 }
T 'simple unknown param' { function g { param($a) "$a|$($args -join ',')" }; g -b 1 }
T 'null split' { $r = $null -split ','; "$(@($r).Count) [$($r[0])]" }
T 'measure count' { $m = (1,2,$null | Measure-Object); "$($m.Count)" }
T 'hex cast' { [int]'0x10' }
T 'pso props on ht' { (@{a=1}).PSObject.Properties.Name -join ',' }
T 'pso props on pso' { ([pscustomobject]@{b=1;a=2}).PSObject.Properties | % { "$($_.Name)=$($_.Value)" } }
T 'bind prefix' { function g { param($LongName) $LongName }; g -Long 5 }
T 'bind switch colon false' { function g { param([switch]$S, $x) "$([bool]$S)|$x" }; g -S:$false 3 }
T 'return in foreach-object' { (1..3 | % { if ($_ -eq 2) { return }; $_ }) -join ',' }
T 'string array param pipeline' { function g { param([string[]]$Type) $Type.Count }; g -Type @('a','b') }
T 'int param from string array' { function g { param([int]$n) $n }; try { g @(1,2) } catch { 'ERR' } }
T 'default expr uses other param' { function g { param($a, $b = $a * 2) $b }; g 3 }
T 'default expr script var' { $script:dv = 7; function g { param($a = $script:dv) $a }; g }
T 'where-object property no op' { @(@([pscustomobject]@{e=$true},[pscustomobject]@{e=$false}) | Where-Object e).Count }
T 'sort unique case strings' { ('b','B','a' | Sort-Object -Unique) -join ',' }
T 'string contains' { 'Hello'.Contains('ell') }
T 'split-path' { "$(Split-Path 'C:\a\b\c.txt') | $(Split-Path 'C:\a\b\c.txt' -Leaf) | $(Split-Path 'c.txt')" }
T 'getextension' { "$([System.IO.Path]::GetExtension('a/b.c.json')) $([System.IO.Path]::GetExtension('a/b')) $([System.IO.Path]::GetFileNameWithoutExtension('x/results.zip'))" }
T 'expand double' { $d = 0.1 * 3; "$d" }
T 'math max type' { [math]::Max(1, 2.5) }
T 'round neg' { [math]::Round(-2.5) }
T 'array eq null' { @(@($null, 1) -eq $null).Count }
T 'switch on array continue' { $r = switch (1,2,3) { 2 { continue } default { $_ } }; $r -join ',' }
T 'switch multiple match' { $r = switch ('a') { 'a' { 1 } 'A' { 2 } }; $r -join ',' }
T 'switch default only when none' { $r = switch ('x') { 'a' { 1 } default { 'd' } }; $r }
T 'string lt culture' { "$('a' -lt 'B') $('Z' -lt 'a') $('_' -lt 'a') $('-' -lt '_')" }
T 'dollar matches after failed match' { 'abc' -match 'b' | Out-Null; 'xyz' -match 'q' | Out-Null; $Matches[0] }
T 'match on array does not set' { $Matches = $null; @('ab') -match 'a' | Out-Null; $null -eq $Matches }
T 'ordered contains value' { $o = [ordered]@{a=1}; "$($o.Contains('a')) $($o.ContainsKey('a'))" }
T 'ordered containskey' { $o = [ordered]@{a=1}; try { $o.ContainsKey('a') } catch { 'ERR ' + $_.Exception.Message } }
T 'list remove' { $l = [System.Collections.Generic.List[object]]::new(); $l.Add('a'); $l.Remove('a') }
T 'if returns' { function g { if ($true) { 'x' } else { 'y' } }; g }
T 'nested function scope write' { function outer { $x = 1; inner; $x }; function inner { $x = 2 }; outer }
T 'script scope var from function' { $script:sv = 1; function g { $script:sv = 5 }; g; $script:sv }
T 'hashtable key int vs string' { $h = @{}; $h[1] = 'int'; "$($h['1']) | $($h[1])" }
T 'sort hashtable enumerator by value' { $h = [ordered]@{a=3;b=1;c=2}; ($h.GetEnumerator() | Sort-Object Value | % Key) -join ',' }
T 'group-object values' { $g = @('x','y','x') | Group-Object; "$($g[0].Values -join ',') $($g[0].Name.GetType().Name)" }
T 'group by scriptblock number' { (@(1,2,3,4) | Group-Object { $_ % 2 } | % { "$($_.Name):$($_.Count)" }) -join ',' }
T 'format neg zero' { (-0.04).ToString('0.#', [cultureinfo]::InvariantCulture) }
T 'dot source param' { $sb = { param($p) $inner = $p }; . $sb 5; $inner }
T 'string -f with array arg' { '{0}-{1}' -f @('a','b') }
T 'pscustomobject property set new' { $o = [pscustomobject]@{a=1}; try { $o.b = 2; 'ok' } catch { 'ERR ' + $_.Exception.Message } }
T 'date formats' { $d = [datetime]::new(2026, 3, 7, 14, 5, 9, [DateTimeKind]::Utc); "$($d.ToString('d MMMM yyyy', [cultureinfo]::InvariantCulture))|$($d.ToString('d MMM', [cultureinfo]::InvariantCulture))|$($d.ToString('d MMMM yyyy, HH:mm', [cultureinfo]::InvariantCulture))|$($d.ToString('yyyy-MM-ddTHH:mm:ssZ', [cultureinfo]::InvariantCulture))|$($d.ToString('yyyyMMdd-HHmmss'))|$($d.ToString('o'))" }
T 'dto parse utc' { ([DateTimeOffset]::Parse('2026-09-19T10:56:58.1234567Z', [cultureinfo]::InvariantCulture)).UtcDateTime.ToString('o') }
T 'dto tryparse' { $p = [DateTimeOffset]::MinValue; $ok = [DateTimeOffset]::TryParse('2026-09-19T10:56:58', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$p); "$ok $($p.UtcDateTime.ToString('o'))" }
T 'dto tryparse bad' { $p = [DateTimeOffset]::MinValue; [DateTimeOffset]::TryParse('nope', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$p) }
T 'unix' { [DateTimeOffset]::FromUnixTimeSeconds(1790000000).UtcDateTime.ToString('o') }
T 'age days' { $ref = [datetime]::new(2026, 9, 1, 0, 0, 0, [DateTimeKind]::Utc); $d = [DateTimeOffset]::Parse('2026-06-01T12:00:00Z').UtcDateTime; [int][math]::Floor(($ref - $d).TotalDays) }
T 'number formats' { $c = [cultureinfo]::InvariantCulture; "$((73.25).ToString('0.#', $c))|$((4).ToString('0.#', $c))|$((66.66666).ToString('0.#', $c))|$((0.05).ToString('0.#', $c))|$((-3.26).ToString('0.#', $c))|$((1234567.891).ToString('0.#', $c))" }
T 'math quirks' { "$([math]::Max(0, [math]::Floor(7.7)))|$([math]::Min(100, 72.5))|$([math]::Max(0.5, 12.25))|$([math]::Round(72.46, 1))|$([math]::Round(-0.05, 1))|$([math]::Ceiling(9 / 8))" }
T 'circumference' { $c = 2 * [math]::PI * 76; $a = [math]::Max(0.01, $c * [double]'73.4' / 100); "$c|$a" }
T 'html encode wide' { [System.Net.WebUtility]::HtmlEncode("<b a='1'>&""x"" é ü ñ " + [char]0x4E2D + ' ' + [char]::ConvertFromUtf32(0x1F600) + '</b>').Replace([string][char]0x4E2D, '<CJK kept>') }
T 'escape data' { [uri]::EscapeDataString("rg name/with?odd#chars&(x)*!'é") }
T 'regex groups' { if ('a1b2' -match '(?<x>\d)(b)(?<y>\d)') { ($Matches.Keys | Sort-Object { [string]$_ }) -join ',' ; "$($Matches[1])|$($Matches.x)|$($Matches.y)" } }
T 'regex groups count' { if ('abc' -match '(a)(?<n>b)(c)') { "$($Matches[1]) $($Matches[2]) $($Matches.n)" } }
T 'replace groups' { "$('2026-09-01' -replace '(\d+)-(\d+)-(\d+)', '$3/$2/$1')|$('abc' -replace '(?<first>a)', '[${first}]')|$('a.b' -replace '\.', '$$')" }
T 'replace case' { 'AbCab' -replace 'ab', 'x' }
T 'split regex' { ('a, b,c' -split ',\s*') -join '|' }
T 'regex matches count' { ([regex]::Matches("x`u{0001}y`u{0002}", '[\x00-\x08\x0E-\x1F]')).Count }
T 'natural key' { [regex]::Replace('NS-9.3.10', '\d+', { param($m) $m.Value.PadLeft(6, '0') }) }
T 'here string' {
    $v = 'X'
    $h = @"
line $v
  "quoted" `$literal
"@
    $h.Replace("`r", '<CR>').Replace("`n", '<LF>')
}
T 'single here' {
    $h = @'
a $b
 c
'@
    $h.Replace("`r", '<CR>').Replace("`n", '<LF>')
}
T 'doubled quotes' { "say ""hi"" $(1 + 1)" }
T 'expand member' { $o = [pscustomobject]@{ a = [pscustomobject]@{ b = 'deep' } }; "v=$($o.a.b) raw=$o.a" }
T 'expand index' { $a = 'x', 'y'; "$($a[1])$a[0]" }
T 'sort case ties' { (('b', 'B', 'a', 'A', 'c', 'C', 'b', 'a') | Sort-Object) -join '' }
T 'sort big ties' { ((1..40 | ForEach-Object { [pscustomobject]@{ k = $_ % 3; i = $_ } }) | Sort-Object k | ForEach-Object i) -join ',' }
T 'sort desc ties' { ((1..20 | ForEach-Object { [pscustomobject]@{ k = $_ % 2; i = $_ } }) | Sort-Object k -Descending | ForEach-Object i) -join ',' }
T 'sort multi desc' { ((1..12 | ForEach-Object { [pscustomobject]@{ a = $_ % 3; b = $_ } }) | Sort-Object { $_.a }, { - $_.b } | ForEach-Object b) -join ',' }
T 'sort strings ids' { (('AZ-STG-010', 'AZ-STG-2', 'AZ-KV-001', 'AZ-IAM-015', 'AZ-IAM-2') | Sort-Object) -join ',' }
T 'group sorted' { ((@('Storage', 'Network', 'storage', 'Identity', 'Network') | Group-Object) | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ',' }
T 'group sort by count' { $g = @('a', 'b', 'b', 'c', 'c', 'c') | Group-Object | Sort-Object { - $_.Count }, Name; ($g | ForEach-Object Name) -join ',' }
T 'measure max obj' { (@([pscustomobject]@{ v = 3 }, [pscustomobject]@{ v = 9 }) | ForEach-Object v | Measure-Object -Maximum).Maximum }
T 'select first skip' { ((1..10 | Select-Object -Skip 2 | Select-Object -First 3)) -join ',' }
T 'where op variants' { (@([pscustomobject]@{ s = 'Fail' }, [pscustomobject]@{ s = 'Pass' }) | Where-Object s -ne 'Pass' | ForEach-Object s) -join ',' }
T 'where in' { (@('a', 'b', 'c') | Where-Object { $_ -in 'a', 'c' }) -join ',' }
T 'bool strings' { "$($true)|$(-not $true)|$([string]$false)" }
T 'ordered json' { [ordered]@{ z = 1; a = @(1, 'two', $null, $true); o = [ordered]@{ n = 1.5 } } | ConvertTo-Json -Depth 5 -Compress }
T 'json array roundtrip' { $j = '[{"a":1},{"a":2}]' | ConvertFrom-Json; "$($j.Count) $($j[1].a)" }
T 'json nested nulls' { $o = '{"a":{"b":null},"c":[]}' | ConvertFrom-Json; "$($null -eq $o.a.b) $(@($o.c).Count) $($o.c.GetType().Name)" }
T 'csv asneeded' { (@([pscustomobject]@{ id = 'AZ-1'; t = 'a, b'; n = 3 }, [pscustomobject]@{ id = 'AZ-2'; t = 'q"x'; n = $null }) | ConvertTo-Csv -NoTypeInformation -UseQuotes AsNeeded) -join '|' }
T 'hashset ignorecase' { $s = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase); $null = $s.Add('Abc'); "$($s.Contains('aBC')) $($s.Add('ABC')) $($s.Count)" }
T 'list getrange' { $l = [System.Collections.Generic.List[object]]::new(); 1..6 | ForEach-Object { $l.Add($_) }; ($l.GetRange(2, 3)) -join ',' }
T 'string methods' { $s = '  /Path/To/'; "$($s.Trim())|$($s.Trim().Trim('/'))|$($s.TrimEnd('/'))|$('abc'.Substring(1))|$('abcdef'.Substring(1, 3))|$('a-b-c'.Split('-').Count)|$('ABC'.ToLowerInvariant())|$('x'.PadLeft(4, '0'))|$('abc'.IndexOf('c'))|$('a.b.c'.LastIndexOf('.'))|$('abc'.StartsWith('ab'))|$('abc'.EndsWith('BC'))|$('a+b'.Replace('+', ' plus '))" }
T 'uint math' { $bytes = @(10, 1, 2, 3); ([uint64]$bytes[0] -shl 24) + ([uint64]$bytes[1] -shl 16) + ([uint64]$bytes[2] -shl 8) + [uint64]$bytes[3] }
T 'uint back' { $n = 167838211; '{0}.{1}.{2}.{3}' -f (($n -shr 24) -band 255), (($n -shr 16) -band 255), (($n -shr 8) -band 255), ($n -band 255) }
T 'ipv6' { $a = $null; $b = $null; $ok = [System.Net.IPAddress]::TryParse('2001:db8::1', [ref]$a) -and [System.Net.IPAddress]::TryParse('2001:db8:ffff::1', [ref]$b); "$ok $($a.AddressFamily) $(($a.GetAddressBytes()) -join '.') $(($b.GetAddressBytes())[4])" }
T 'base64' { $b = [Convert]::FromBase64String('aGVsbG8gd29ybGQ='); "$($b.Length) $([System.Text.Encoding]::UTF8.GetString($b))" }
T 'base64 bad' { try { [Convert]::FromBase64String('###') } catch { 'caught' } }
T 'timespan iso' { $t = [System.Xml.XmlConvert]::ToTimeSpan('PT8H'); "$($t.TotalHours) $($t.TotalDays) $([System.Xml.XmlConvert]::ToTimeSpan('P180D').TotalDays)" }
T 'version tryparse' { $v = $null; $normalized = 'TLS1_2' -replace '(?i)^tls\s*v?', '' -replace '_', '.'; "$([version]::TryParse($normalized, [ref]$v)) $($v -ge [version]'1.2')" }
T 'switch regex matches' { $r = switch -Regex ('Tls12') { '^Tls(\d)(\d)$' { "$($Matches[1]).$($Matches[2])" } }; $r }
T 'param validate' { function g { param([ValidateSet('A', 'B')][string]$x) $x }; try { g 'c' } catch { $_.Exception.Message } }
T 'param mandatory null' { function g { param([Parameter(Mandatory = $true)]$x) $x }; try { g -x $null } catch { $_.Exception.Message } }
T 'param mandatory missing' { function g { [CmdletBinding()] param([Parameter(Mandatory = $true)][string]$x) $x }; try { g } catch { 'missing' } }
T 'error line' { function g { $null.Nope() }; try { g } catch { "$($_.Exception.Message)|$($_.InvocationInfo.ScriptLineNumber -gt 0)" } }
T 'throw object' { try { throw 'custom failure' } catch { "$($_.Exception.Message)|$_" } }
T 'nested catch rethrow' { try { try { throw 'inner' } catch { throw } } catch { $_.Exception.Message } }
T 'finally order' { $log = [System.Collections.Generic.List[string]]::new(); try { $log.Add('try') } finally { $log.Add('finally') }; $log -join ',' }
T 'string join method' { [string]::Join('-', @('a', 'b')) }
T 'isnullorempty' { "$([string]::IsNullOrEmpty($null)) $([string]::IsNullOrEmpty('')) $([string]::IsNullOrWhiteSpace(' '))" }
T 'getenumerator sort' { $h = @{ b = 2; a = 1 }; ($h.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ',' }
T 'hashtable foreach keys' { $h = [ordered]@{ x = 1; y = 2 }; $s = 0; foreach ($k in $h.Keys) { $s += $h[$k] }; $s }
T 'dynamic member' { $o = [pscustomobject]@{ 'my-prop' = 5 }; $n = 'my-prop'; "$($o.$n) $($o.'my-prop')" }
T 'psobject properties' { $o = [pscustomobject]@{ b = 1; a = $null }; (@($o.PSObject.Properties) | ForEach-Object { "$($_.Name):$($null -eq $_.Value)" }) -join ',' }
T 'array of arrays' { $rows = @(, @('a', 1), , @('b', 2)); $rows.Count }
T 'array of arrays comma' { $rows = @(
        , @('a', 1)
        , @('b', 2)
    ); "$($rows.Count) $($rows[1][0])" }
T 'multi assign array' { $x, $y, $z = @('p', 'q'); "$x|$y|$($null -eq $z)" }
T 'increment member' { $o = [ordered]@{ n = 1 }; $o.n++; $o['m']++; "$($o.n) $($o.m)" }
T 'compound assign' { $a = @(1); $a += 2; $a += @(3, 4); $s = 'x'; $s += 5; "$($a -join ',') $s" }
T 'while break continue' { $i = 0; $out = @(); while ($true) { $i++; if ($i -eq 2) { continue }; if ($i -gt 4) { break }; $out += $i }; $out -join ',' }
T 'for loop' { $s = ''; for ($i = 0; $i -lt 3; $i++) { $s += $i }; $s }
T 'nested function dynamic scope' { $script:counter = 0; function bump { $script:counter++ }; bump; bump; $script:counter }
T 'scriptblock invoke args' { $x = { param([int]$Index) $Index * 2 }; & $x 4 }
T 'scriptblock closure dynamic' { $factor = 3; $mul = { param($v) $v * $factor }; function inner { $factor = 10; & $mul 2 }; "$(& $mul 2) $(inner)" }
T 'if assignment value' { $v = if ($false) { 'a' } elseif ($true) { 'b' } else { 'c' }; $v }
T 'switch assignment value' { $v = switch ('x') { 'y' { 1 } default { 'dflt' } }; $v }
T 'foreach assignment value' { $v = foreach ($i in 1..3) { $i * 2 }; "$($v -join ',') $($v.GetType().Name)" }
T 'subexpression multi' { "$(1; 2; 3)" }
T 'array expression multi' { @(1; @(2, 3); $null).Count }
T 'format number string' { '{0} of {1}' -f 3, 7 }
T 'is checks' { "$('x' -is [string]) $(5 -is [int]) $(@() -is [array]) $($null -is [object]) $([pscustomobject]@{} -is [pscustomobject])" }
T 'cast bool list' { "$([bool]@()) $([bool]@(1)) $([bool]'') $([bool]$null)" }
T 'like wildcard' { "$('dataMaskingPolicies/Default' -like 'dataMaskingPolicies*') $('abc' -like '*B*') $('a.b' -like 'a?b') $('x' -notlike 'y*')" }
T 'contains in variants' { "$(@('A', 'B') -contains 'a') $('a' -notin @('b')) $(@(1, 2) -notcontains 3)" }
T 'match on number' { 123 -match '^\d+$' }
T 'null coalescing' { $x = $null; $y = $x ?? 'fallback'; $y }
T 'exclaim' { "$(!$true) $(!'') $(!@())" }
T 'unary minus on sort' { (@(3, 1, 2) | Sort-Object { - $_ }) -join ',' }
T 'range reverse' { (5..3) -join ',' }
T 'string multiply join' { ('-' * 3) + '|' + ((1..3 | ForEach-Object { 'x' }) -join '') }
T 'int division exact' { "$(10 / 5) $(7 % 3) $(-7 % 3)" }
T 'double compare strings' { "$(10 -gt 9.5) $('10' -gt '9')" }
T 'char compare' { 'b' -in @('a', 'b') }
T 'backtick escapes' { "tab[`t]nl[`n]dq[`"]bt[``]dollar[`]" }
T 'backtick unicode length' { "`u{263A}`u{1F600}".Length }
T 'f formats' { '{0:00}|{1}|{0:D3}' -f 7, 'x' }
