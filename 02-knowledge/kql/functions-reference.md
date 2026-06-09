# KQL Functions Reference

Source: learn.microsoft.com/en-us/azure/data-explorer/kusto/query/

---

## Aggregation functions (used inside summarize)

| Function | Description | Example |
|---|---|---|
| `count()` | Total row count | `summarize count()` |
| `countif(pred)` | Conditional count | `summarize countif(Result=="Failed")` |
| `dcount(col)` | Approximate distinct count | `summarize dcount(IPAddress)` |
| `dcountif(col, pred)` | Conditional distinct count | `summarize dcountif(User, Failed==true)` |
| `sum(col)` | Sum | `summarize sum(BytesSent)` |
| `sumif(col, pred)` | Conditional sum | `summarize sumif(Bytes, Direction=="out")` |
| `avg(col)` | Average | `summarize avg(Duration)` |
| `min(col)` | Minimum | `summarize min(TimeGenerated)` |
| `max(col)` | Maximum | `summarize max(TimeGenerated)` |
| `percentile(col, p)` | Nth percentile | `summarize percentile(Duration, 95)` |
| `stdev(col)` | Standard deviation | `summarize stdev(Score)` |
| `arg_max(col, *)` | Row with max col value | `summarize arg_max(TimeGenerated, *)` |
| `arg_min(col, *)` | Row with min col value | `summarize arg_min(TimeGenerated, *)` |
| `make_list(col)` | Array of all values | `summarize make_list(EventID)` |
| `make_list_if(col, pred)` | Conditional array | `summarize make_list_if(IP, isnotempty(IP))` |
| `make_set(col)` | Array of distinct values | `summarize make_set(AccountName)` |
| `make_set_if(col, pred)` | Conditional distinct set | `summarize make_set_if(IP, isnotempty(IP))` |

---

## String functions

| Function | Description |
|---|---|
| `tolower(s)` | Lowercase |
| `toupper(s)` | Uppercase |
| `trim(regex, s)` | Trim leading/trailing |
| `ltrim(regex, s)` | Trim leading |
| `rtrim(regex, s)` | Trim trailing |
| `strlen(s)` | String length |
| `substring(s, start, len)` | Substring |
| `strcat(s1, s2, ...)` | Concatenate |
| `strcat_array(arr, delim)` | Join array to string |
| `split(s, delim)` | Split to array |
| `split(s, delim, idx)` | Split and get index |
| `indexof(s, substr)` | First position of substr (-1 if absent) |
| `replace_string(s, old, new)` | Replace substring |
| `replace_regex(s, regex, repl)` | Regex replace |
| `extract(regex, captureGroup, s)` | Regex extract |
| `extract_all(regex, s)` | All regex matches |
| `parse_url(url)` | Parse URL to dynamic |
| `parse_urlquery(query)` | Parse query string |
| `url_decode(s)` | URL decode |
| `url_encode(s)` | URL encode |
| `base64_decode_tostring(s)` | Decode base64 |
| `base64_encode_tostring(s)` | Encode base64 |
| `hash(val, mod)` | Hash value |
| `isempty(s)` | True if null or "" |
| `isnotempty(s)` | True if not null and not "" |
| `isnull(val)` | True if null |
| `isnotnull(val)` | True if not null |

---

## Type conversion

| Function | Description |
|---|---|
| `tostring(val)` | Convert to string |
| `toint(val)` | Convert to int32 |
| `tolong(val)` | Convert to int64 |
| `toreal(val)` | Convert to float |
| `tobool(val)` | Convert to bool |
| `todatetime(val)` | Convert to datetime |
| `totimespan(val)` | Convert to timespan |
| `todynamic(val)` | Convert to dynamic/JSON |
| `toDecimal(val)` | Convert to decimal |

---

## Datetime functions

| Function | Description |
|---|---|
| `now()` | Current UTC time |
| `ago(timespan)` | Time in the past |
| `datetime(literal)` | Datetime literal e.g. datetime(2024-01-01) |
| `bin(val, roundTo)` | Round down to bin |
| `floor(val, roundTo)` | Same as bin |
| `ceiling(val, roundTo)` | Round up |
| `startofday(dt)` | Start of day |
| `endofday(dt)` | End of day |
| `startofweek(dt)` | Start of week (Sunday) |
| `startofmonth(dt)` | Start of month |
| `startofyear(dt)` | Start of year |
| `hourofday(dt)` | Hour 0-23 |
| `dayofweek(dt)` | Day of week as timespan |
| `dayofmonth(dt)` | Day 1-31 |
| `dayofyear(dt)` | Day 1-366 |
| `monthofyear(dt)` | Month 1-12 |
| `getyear(dt)` | Year |
| `datetime_diff(part, dt1, dt2)` | Difference in units |
| `datetime_add(part, val, dt)` | Add to datetime |
| `format_datetime(dt, format)` | Format as string |
| `format_timespan(ts, format)` | Format timespan |

---

## Numeric functions

| Function | Description |
|---|---|
| `abs(n)` | Absolute value |
| `round(n, d)` | Round to d decimals |
| `floor(n, step)` | Floor to step |
| `ceiling(n, step)` | Ceiling to step |
| `log(n)` | Natural log |
| `log2(n)` | Log base 2 |
| `log10(n)` | Log base 10 |
| `exp(n)` | e^n |
| `sqrt(n)` | Square root |
| `pow(base, exp)` | base^exp |
| `rand()` | Random 0-1 |
| `sign(n)` | -1, 0, or 1 |

---

## IP functions

| Function | Description |
|---|---|
| `ipv4_is_private(ip)` | True if RFC1918 |
| `ipv4_is_in_range(ip, range)` | True if in CIDR |
| `ipv4_compare(ip1, ip2)` | Compare IPs as integers |
| `ipv6_is_in_range(ip, range)` | IPv6 CIDR check |
| `parse_ipv4(ip)` | Parse to long |
| `parse_ipv6(ip)` | Normalize IPv6 |
| `format_ipv4(long)` | Long to dotted decimal |

---

## Array/Dynamic functions

| Function | Description |
|---|---|
| `array_length(arr)` | Array length |
| `array_index_of(arr, val)` | Index of value |
| `array_concat(arr1, arr2)` | Concatenate arrays |
| `array_slice(arr, start, end)` | Slice array |
| `array_split(arr, idx)` | Split array at index |
| `set_union(s1, s2)` | Union of two sets |
| `set_intersect(s1, s2)` | Intersection |
| `set_difference(s1, s2)` | Difference |
| `bag_merge(b1, b2)` | Merge property bags |
| `bag_keys(b)` | Keys of property bag |
| `pack(key, val, ...)` | Create property bag |
| `pack_array(v1, v2, ...)` | Create array |
| `zip(arr1, arr2)` | Zip two arrays |

---

## Conditional functions

| Function | Description |
|---|---|
| `iff(cond, true, false)` | Ternary |
| `iif(cond, true, false)` | Alias for iff |
| `case(c1, v1, c2, v2, ..., default)` | Multi-branch |
| `coalesce(v1, v2, ...)` | First non-null |

---

## Watchlist / threat intelligence

```kql
// Access a Sentinel watchlist
_GetWatchlist('WatchlistAlias')
| project SearchKey, Notes

// Threat intelligence lookup
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(14d)
| where isnotempty(NetworkIP)
| project NetworkIP, ThreatType, Confidence
```
