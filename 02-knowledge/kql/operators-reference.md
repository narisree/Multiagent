# KQL Tabular Operators Reference

Source: learn.microsoft.com/en-us/azure/data-explorer/kusto/query/

---

## Filtering

### where
```kql
T | where <predicate>
T | where TimeGenerated >= ago(1h)
T | where EventID == 4625
T | where tolower(AccountName) contains "admin"
T | where Status in ("Failed", "Error")
```

### search
```kql
search "error"                    // searches all tables
search in (SecurityEvent) "error" // limits to one table
T | search "keyword"
```

---

## Column operations

### project
```kql
T | project TimeGenerated, AccountName, Computer, EventID
T | project-away SomeColumnToRemove
T | project-rename NewName = OldName
```

### extend
```kql
T | extend UpperAccount = toupper(AccountName)
T | extend IsFailure = iff(Result == "Failure", true, false)
T | extend ParsedData = parse_json(RawData)
```

### parse (extract structured fields from strings)
```kql
T | parse Message with * "user=" UserName " " *
T | parse kind=regex Message with @"user=(?P<UserName>\S+)"
```

---

## Aggregation

### summarize
```kql
T | summarize count() by AccountName
T | summarize EventCount = count(), UniqueIPs = dcount(IPAddress) by AccountName, bin(TimeGenerated, 1h)
T | summarize arg_max(TimeGenerated, *) by AccountName  // latest record per account
T | summarize make_list(EventID) by Computer             // list of values
T | summarize make_set(AccountName) by Computer          // distinct values as set
```

**Important:** Always specify `by` when grouping is intended. `summarize` without `by` returns a single row.

---

## Joins

### join
```kql
T1
| join kind=inner (T2) on AccountName

T1
| join kind=leftouter (
    T2
    | where TimeGenerated >= ago(1h)
) on $left.AccountName == $right.Name
```

**Join kinds:**
| Kind | Behavior |
|---|---|
| `inner` | Rows matched in both; multiple matches expanded |
| `innerunique` | Default — deduplicates left side first (can miss rows) |
| `leftouter` | All left rows; nulls for unmatched right |
| `rightouter` | All right rows; nulls for unmatched left |
| `fullouter` | All rows from both sides |
| `leftanti` | Left rows NOT in right |
| `rightanti` | Right rows NOT in left |
| `leftsemi` | Left rows where match exists in right (no right columns) |

**Always specify `kind=` explicitly.** `innerunique` is the default and silently deduplicates.

### lookup
```kql
T | lookup WatchlistTable on AccountName   // efficient left join against small reference table
```

---

## Sorting and limiting

```kql
T | sort by TimeGenerated desc
T | order by EventCount desc
T | top 10 by EventCount desc
T | limit 100
T | take 100      // same as limit
```

---

## Set operations

```kql
T1 | union T2
T1 | union kind=outer T2    // include all columns
T1 | union withsource=TableName T2, T3
T | distinct Column1, Column2
```

---

## String operators

| Operator | Case | Contains whole term? |
|---|---|---|
| `contains` | insensitive | substring |
| `!contains` | insensitive | not substring |
| `contains_cs` | sensitive | substring |
| `has` | insensitive | whole term |
| `has_cs` | sensitive | whole term |
| `has_any` | insensitive | any of list |
| `has_all` | insensitive | all of list |
| `startswith` | insensitive | prefix |
| `endswith` | insensitive | suffix |
| `matches regex` | sensitive | regex match |
| `=~` | insensitive | equals |
| `==` | sensitive | equals |

**Use `has` over `contains` for better performance on indexed string fields.**

---

## Dynamic / JSON operators

```kql
T | extend Parsed = parse_json(RawData)
T | extend IP = tostring(Parsed.sourceIPAddress)
T | mv-expand Tags           // expand array to rows
T | mv-apply Tag = Tags to typeof(string) on (where Tag startswith "prod")
T | evaluate bag_unpack(Properties)   // expand property bag to columns
```

---

## Conditional / scalar operators

```kql
| extend Label = iff(Score > 50, "High", "Low")
| extend Category = case(
    Score >= 90, "Critical",
    Score >= 70, "High",
    Score >= 40, "Medium",
    "Low")
| extend Value = coalesce(Field1, Field2, "default")
| where isnotempty(AccountName)
| where isnotnull(IPAddress)
```

---

## let statements

```kql
let lookback = ago(1h);
let threshold = 5;
let suspiciousIPs = datatable(IP:string) ["1.2.3.4", "5.6.7.8"];
let watchlist = (_GetWatchlist('MyWatchlist') | project SearchKey, Notes);
SecurityEvent
| where TimeGenerated >= lookback
```

`let` bindings are scoped to the query. Define all constants at the top.

---

## Time operators

```kql
| where TimeGenerated >= ago(1h)         // last 1 hour
| where TimeGenerated >= ago(24h)        // last 24 hours
| where TimeGenerated between (ago(7d) .. now())
| summarize count() by bin(TimeGenerated, 1h)   // bucket by 1-hour bins
| extend HourOfDay = hourofday(TimeGenerated)
| extend DayOfWeek = dayofweek(TimeGenerated)
```

See `kql/time-operators.md` for full time syntax reference.

---

## make-series (time series)

```kql
T
| make-series EventCount = count() default=0
    on TimeGenerated from ago(7d) to now() step 1h
    by AccountName
| extend Anomalies = series_decompose_anomalies(EventCount)
```

---

## evaluate plugins

```kql
| evaluate autocluster()        // find common patterns
| evaluate basket()             // association rules
| evaluate diffpatterns(...)    // compare two populations
| evaluate bag_unpack(Column)   // expand property bag
```
