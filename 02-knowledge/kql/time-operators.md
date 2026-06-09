# KQL Time Operators & Syntax

---

## Timespan literals

```
1d       = 1 day
1h       = 1 hour
30m      = 30 minutes
5s       = 5 seconds
1.5h     = 1 hour 30 minutes
7d       = 7 days
```

---

## ago() — relative time filter (most common)

```kql
| where TimeGenerated >= ago(1h)     // last 1 hour
| where TimeGenerated >= ago(24h)    // last 24 hours
| where TimeGenerated >= ago(7d)     // last 7 days
| where TimeGenerated >= ago(30d)    // last 30 days
```

**Standard pattern (house style):**
```kql
let lookback = ago(1h);
T | where TimeGenerated >= lookback
```

---

## between — time range

```kql
| where TimeGenerated between (ago(7d) .. now())
| where TimeGenerated between (datetime(2024-01-01) .. datetime(2024-01-31))
```

---

## bin() — time bucketing for summarize

```kql
| summarize count() by bin(TimeGenerated, 1h)    // hourly buckets
| summarize count() by bin(TimeGenerated, 5m)    // 5-minute buckets
| summarize count() by bin(TimeGenerated, 1d)    // daily buckets
```

---

## datetime literals

```kql
datetime(2024-01-15)                     // date only
datetime(2024-01-15 14:30:00)            // date + time (UTC)
datetime(2024-01-15T14:30:00Z)           // ISO 8601
todatetime("2024-01-15")                 // from string
```

---

## now()

```kql
now()                    // current UTC time
now(-1h)                 // 1 hour ago (same as ago(1h))
now(1d)                  // 1 day in the future
```

---

## startof* / endof*

```kql
startofday(now())        // 2024-01-15 00:00:00
endofday(now())          // 2024-01-15 23:59:59.999
startofweek(now())       // most recent Sunday 00:00:00
startofmonth(now())      // first of current month
startofyear(now())       // Jan 1 of current year
```

---

## Date extraction

```kql
| extend HourOfDay   = hourofday(TimeGenerated)     // 0-23
| extend DayOfWeek   = dayofweek(TimeGenerated)     // 0d=Sun, 1d=Mon...
| extend DayOfMonth  = dayofmonth(TimeGenerated)    // 1-31
| extend MonthOfYear = monthofyear(TimeGenerated)   // 1-12
| extend Year        = getyear(TimeGenerated)
```

---

## datetime_diff

```kql
datetime_diff("hour",   datetime(2024-01-15 15:00), datetime(2024-01-15 12:00))  // = 3
datetime_diff("minute", EndTime, StartTime)
datetime_diff("second", LogoutTime, LoginTime)
datetime_diff("day",    now(), datetime(2024-01-01))
```

Units: "year", "quarter", "month", "week", "day", "hour", "minute", "second", "millisecond", "microsecond", "nanosecond"

---

## format_datetime

```kql
| extend DateStr = format_datetime(TimeGenerated, "yyyy-MM-dd HH:mm")
| extend DateOnly = format_datetime(TimeGenerated, "yyyy-MM-dd")
```

---

## ISO 8601 durations (used in ARM templates)

Sentinel rule metadata uses ISO 8601, NOT KQL timespan literals:

| KQL | ISO 8601 (ARM) |
|---|---|
| `5m` | `PT5M` |
| `15m` | `PT15M` |
| `30m` | `PT30M` |
| `1h` | `PT1H` |
| `4h` | `PT4H` |
| `12h` | `PT12H` |
| `1d` | `P1D` |
| `2d` | `P2D` |
| `7d` | `P7D` |
| `14d` | `P14D` |

**Common pairs:**
| queryFrequency | queryPeriod | Use case |
|---|---|---|
| PT5M | PT5M | Near-real-time, noisy sources |
| PT1H | PT1H | Standard hourly rule |
| PT1H | PT24H | Look back a day, run hourly |
| PT5H | PT1D | Threat intel correlation |
| P1D | P7D | Low-frequency detections |

**Rule:** queryPeriod must be ≥ queryFrequency.

---

## make-series (time series analytics)

```kql
T
| make-series EventCount = count() default=0
    on TimeGenerated
    from ago(7d) to now()
    step 1h
    by AccountName
| extend (Anomalies, Score, Baseline) = series_decompose_anomalies(EventCount)
| mv-expand TimeGenerated, EventCount, Anomalies, Score, Baseline
| where Anomalies > 0
```
