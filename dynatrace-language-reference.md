# Dynatrace Query Language (DQL) Reference

> **LLM Context**: This is the comprehensive DQL reference. For quick queries, see `dynatrace-language-rule.md`. This document is also available as an MCP resource via `resources/list` and can be fetched programmatically.

This comprehensive reference documents the Dynatrace Query Language for use with Dynatrace Grail data lakehouse. DQL is a powerful, pipeline-based query language for analyzing observability data.

## Table of Contents

1. [Query Structure and Syntax](#query-structure-and-syntax)
2. [Data Sources](#data-sources)
3. [Data Types](#data-types)
4. [Operators](#operators)
5. [Commands](#commands)
6. [Functions](#functions)
7. [Pattern Language (DPL)](#pattern-language-dpl)
8. [Best Practices](#best-practices)

---

## Query Structure and Syntax

### Basic Query Structure

DQL queries use a pipeline syntax where data flows through a series of commands separated by the pipe (`|`) operator:

```dql
fetch logs
| filter loglevel == "ERROR"
| fields timestamp, content
| sort timestamp desc
| limit 100
```

### Key Syntax Rules

- **Case Sensitivity**: Keywords are case-insensitive (`FETCH` = `fetch`), but field names and string values are case-sensitive
- **Comments**: Use `//` for single-line comments
- **String Literals**: Use double quotes `"string"` or single quotes `'string'`
- **Field Access**: Use dot notation for nested fields: `entity.name`
- **Array Access**: Use bracket notation: `array[0]`
- **Time Literals**: Use ISO 8601 format or relative times: `now() - 1h`

### Query Pipeline Flow

```
fetch <source> → filter → transform → aggregate → sort → limit → output
```

---

## Data Sources

### fetch Command

The `fetch` command is the starting point for all DQL queries:

```dql
fetch <data_source>, [from: <start_time>], [to: <end_time>], [scanLimitGBytes: <limit>]
```

### Available Data Sources

| Source | Description | Common Fields |
|--------|-------------|---------------|
| `logs` | Log records from all monitored sources | `timestamp`, `content`, `loglevel`, `log.source`, `dt.entity.*` |
| `events` | Davis events and custom events | `timestamp`, `event.type`, `event.name`, `event.kind`, `dt.entity.*` |
| `metrics` | Metric data points | `timestamp`, `metric.key`, `value`, `dimensions` |
| `spans` | Distributed trace spans | `timestamp`, `span.name`, `span.kind`, `trace.id`, `span.id`, `duration` |
| `entities` | Monitored entity metadata | `entity.type`, `entity.name`, `id`, `tags`, `properties` |
| `bizevents` | Business events | `timestamp`, `event.type`, `event.provider`, custom attributes |
| `dt.system.events` | Dynatrace system events | `timestamp`, `event.type`, `event.description` |
| `security_events` | Security-related events | `timestamp`, `event.type`, `severity`, `attack.type` |

### Time Range Parameters

```dql
// Explicit time range
fetch logs, from: now() - 2h, to: now()

// Relative time shortcuts
fetch logs, from: -24h

// Absolute timestamps
fetch logs, from: "2024-01-15T00:00:00Z", to: "2024-01-15T23:59:59Z"

// Timeframe function
fetch logs, from: timeframe(from: now() - 1d, to: now())
```

### Scan Limits

```dql
// Limit data scanned to 500 GB
fetch logs, scanLimitGBytes: 500
```

### Bucket Filtering (Performance Optimization)

```dql
// Filter logs from specific bucket
fetch logs
| filter matchesPhrase(dt.system.bucket, "default_logs")
```

---

## Data Types

### Primitive Types

| Type | Description | Example |
|------|-------------|---------|
| `boolean` | True or false values | `true`, `false` |
| `long` | 64-bit signed integer | `42`, `-100`, `9223372036854775807` |
| `double` | 64-bit floating point | `3.14159`, `-273.15`, `1.0e10` |
| `string` | Unicode text | `"hello"`, `'world'` |
| `timestamp` | Point in time (nanosecond precision) | `2024-01-15T10:30:00.000000000Z` |
| `duration` | Time duration | `1h`, `30m`, `45s`, `100ms`, `1000us`, `1000000ns` |
| `timeframe` | Time range with start and end | `timeframe(from: now()-1h, to: now())` |
| `ip` | IPv4 or IPv6 address | `ip("192.168.1.1")`, `ip("::1")` |
| `uid` | Unique identifier | Binary 128-bit identifier |

### Complex Types

| Type | Description | Example |
|------|-------------|---------|
| `array` | Ordered collection of values | `["a", "b", "c"]`, `[1, 2, 3]` |
| `record` | Key-value structure | `record(name: "test", value: 42)` |

### Type Conversion Functions

```dql
// Convert to string
toString(123)                    // "123"
toString(true)                   // "true"
toString(timestamp)              // ISO 8601 string

// Convert to numeric
toLong("123")                    // 123
toDouble("3.14")                 // 3.14

// Convert to timestamp
toTimestamp("2024-01-15T10:00:00Z")
toTimestamp(1705315200000)       // From Unix milliseconds

// Convert to duration
toDuration(3600000000000)        // 1h (from nanoseconds)

// Convert to IP
toIp("192.168.1.1")

// Convert to array
toArray(value)                   // Wraps value in array if not already
```

### Null Handling

```dql
// Check for null
isNull(field)
isNotNull(field)

// Coalesce (first non-null value)
coalesce(field1, field2, "default")

// Null-safe field access
record[field]                    // Returns null if field doesn't exist
```

---

## Operators

### Comparison Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `==` | Equal | `status == 200` |
| `!=` | Not equal | `status != 404` |
| `<` | Less than | `response_time < 1000` |
| `<=` | Less than or equal | `response_time <= 500` |
| `>` | Greater than | `error_count > 0` |
| `>=` | Greater than or equal | `cpu_usage >= 80` |

### Logical Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `and` | Logical AND | `status == 500 and response_time > 1000` |
| `or` | Logical OR | `loglevel == "ERROR" or loglevel == "WARN"` |
| `not` | Logical NOT | `not isNull(error_message)` |

### Pattern Matching Operator

| Operator | Description | Example |
|----------|-------------|---------|
| `~` | Pattern match (Davis Pattern Language) | `content ~ "error.*timeout"` |

### Membership Operator

```dql
// Check if value is in a set
status in (200, 201, 204)
loglevel in ("ERROR", "WARN", "FATAL")

// Negated membership
status not in (500, 502, 503)
```

### Arithmetic Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `+` | Addition | `a + b`, string concatenation |
| `-` | Subtraction | `total - used` |
| `*` | Multiplication | `rate * 100` |
| `/` | Division | `total / count` |
| `%` | Modulo | `id % 10` |

### Time Alignment Operator

```dql
// Align timestamp to interval boundary
timestamp @ 1h          // Align to hour
timestamp @ 5m          // Align to 5 minutes
timestamp @ 1d          // Align to day
```

### String Concatenation

```dql
// Using + operator
"prefix_" + field_name + "_suffix"

// Using concat function
concat("prefix_", field_name, "_suffix")
```

---

## Commands

### Data Retrieval

#### fetch
```dql
fetch logs, from: now() - 1h, to: now()
fetch metrics, scanLimitGBytes: 100
fetch entities
```

### Filtering Commands

#### filter
Keeps records matching the condition:
```dql
fetch logs
| filter loglevel == "ERROR"
| filter contains(content, "database")
```

#### filterOut
Removes records matching the condition:
```dql
fetch logs
| filterOut loglevel == "DEBUG"
| filterOut contains(content, "healthcheck")
```

### Field Selection and Transformation

#### fields
Selects and optionally renames fields:
```dql
fetch logs
| fields timestamp, content, level: loglevel

// Only specified fields are kept
```

#### fieldsAdd
Adds new computed fields while keeping all existing:
```dql
fetch logs
| fieldsAdd response_ms: response_time / 1000000,
            has_error: contains(content, "error")
```

#### fieldsRemove
Removes specified fields:
```dql
fetch logs
| fieldsRemove internal_id, debug_data
```

#### fieldsKeep
Keeps only specified fields (alias for `fields`):
```dql
fetch logs
| fieldsKeep timestamp, content, loglevel
```

#### fieldsRename
Renames fields without removing others:
```dql
fetch logs
| fieldsRename level: loglevel, msg: content
```

### Aggregation

#### summarize
Groups and aggregates data:
```dql
fetch logs
| summarize count(), by: {loglevel}

fetch logs
| summarize
    error_count = countIf(loglevel == "ERROR"),
    warn_count = countIf(loglevel == "WARN"),
    by: {host.name, bin(timestamp, 1h)}
```

### Sorting and Limiting

#### sort
Orders results:
```dql
fetch logs
| sort timestamp desc

fetch logs
| sort loglevel asc, timestamp desc
```

#### limit
Restricts result count:
```dql
fetch logs
| limit 100

// First N (equivalent to limit)
fetch logs
| limit 50
```

### Parsing and Extraction

#### parse
Extracts structured data from strings using DPL:
```dql
fetch logs
| parse content, "LD 'status=' INT:status LD 'duration=' INT:duration 'ms'"

fetch logs
| parse content, """
    IP:client_ip
    SPACE
    LD:method
    SPACE
    LD:path
    SPACE
    INT:status
"""
```

### Combining Data

#### lookup
Enriches data with lookup table:
```dql
fetch logs
| lookup [fetch entities | fields entity_id: id, entity_name: entity.name],
         sourceField: dt.entity.host, lookupField: entity_id
```

#### join
Joins two result sets:
```dql
fetch logs
| join [fetch entities], on: {left[dt.entity.host] == right[id]}, kind: left
```

Join types:
- `inner` - Only matching records
- `left` - All left records, matching right
- `right` - All right records, matching left
- `outer` - All records from both sides

#### append
Combines results from multiple queries:
```dql
fetch logs, from: now() - 1h
| filter loglevel == "ERROR"
| append [
    fetch events, from: now() - 1h
    | filter event.type == "ERROR_EVENT"
]
```

### Array Operations

#### expand
Flattens array field into multiple records:
```dql
fetch logs
| expand tags
```

#### array operations in fields
```dql
fetch logs
| fieldsAdd first_tag: tags[0],
            tag_count: size(tags)
```

### Time Series

#### timeseries
Creates time series from data:
```dql
timeseries avg(dt.host.cpu.usage), by: {dt.entity.host}, interval: 5m
```

#### makeTimeseries
Converts aggregated data to time series:
```dql
fetch logs
| summarize count(), by: {bin(timestamp, 5m), host.name}
| makeTimeseries count(), by: {host.name}, time: timestamp
```

### Subqueries

```dql
fetch logs
| filter dt.entity.host in [
    fetch entities
    | filter entity.type == "HOST"
    | filter matchesValue(tags, "environment:production")
    | fields id
]
```

---

## Functions

### Aggregation Functions

| Function | Description | Example |
|----------|-------------|---------|
| `count()` | Count of records | `summarize count()` |
| `countIf(condition)` | Conditional count | `summarize countIf(status >= 400)` |
| `countDistinct(field)` | Count unique values | `summarize countDistinct(user_id)` |
| `countDistinctApprox(field)` | Approximate distinct count (faster) | `summarize countDistinctApprox(session_id)` |
| `sum(field)` | Sum of values | `summarize sum(bytes)` |
| `avg(field)` | Average value | `summarize avg(response_time)` |
| `min(field)` | Minimum value | `summarize min(timestamp)` |
| `max(field)` | Maximum value | `summarize max(duration)` |
| `median(field)` | Median value | `summarize median(latency)` |
| `percentile(field, p)` | Percentile value | `summarize percentile(latency, 95)` |
| `stddev(field)` | Standard deviation | `summarize stddev(response_time)` |
| `variance(field)` | Variance | `summarize variance(metric)` |
| `first(field)` | First value in group | `summarize first(message)` |
| `last(field)` | Last value in group | `summarize last(status)` |
| `takeFirst(field)` | First non-null value | `summarize takeFirst(error_msg)` |
| `takeLast(field)` | Last non-null value | `summarize takeLast(status_msg)` |
| `takeAny(field)` | Any value from group | `summarize takeAny(host)` |
| `collectArray(field)` | Collect into array | `summarize collectArray(tag)` |
| `collectDistinct(field)` | Collect unique values | `summarize collectDistinct(user)` |

### String Functions

| Function | Description | Example |
|----------|-------------|---------|
| `contains(str, substr)` | Check if contains substring | `contains(content, "error")` |
| `startsWith(str, prefix)` | Check if starts with | `startsWith(path, "/api/")` |
| `endsWith(str, suffix)` | Check if ends with | `endsWith(filename, ".log")` |
| `matches(str, pattern)` | Regex match | `matches(content, "error\\d+")` |
| `matchesPhrase(str, phrase)` | Token-aware phrase match | `matchesPhrase(content, "connection timeout")` |
| `matchesValue(array, value)` | Check array contains value | `matchesValue(tags, "prod")` |
| `indexOf(str, substr)` | Find position of substring | `indexOf(path, "/")` |
| `substring(str, start, end)` | Extract substring | `substring(content, 0, 100)` |
| `left(str, n)` | First n characters | `left(content, 50)` |
| `right(str, n)` | Last n characters | `right(filename, 4)` |
| `trim(str)` | Remove leading/trailing whitespace | `trim(value)` |
| `lower(str)` | Convert to lowercase | `lower(method)` |
| `upper(str)` | Convert to uppercase | `upper(status)` |
| `replace(str, old, new)` | Replace occurrences | `replace(path, "/v1/", "/v2/")` |
| `replacePattern(str, pattern, new)` | Regex replace | `replacePattern(content, "\\d+", "X")` |
| `split(str, delimiter)` | Split into array | `split(tags, ",")` |
| `concat(str1, str2, ...)` | Concatenate strings | `concat(host, ":", port)` |
| `size(str)` | String length | `size(content)` |

### Mathematical Functions

| Function | Description | Example |
|----------|-------------|---------|
| `abs(n)` | Absolute value | `abs(difference)` |
| `ceil(n)` | Round up | `ceil(value)` |
| `floor(n)` | Round down | `floor(value)` |
| `round(n, precision)` | Round to precision | `round(percentage, 2)` |
| `sqrt(n)` | Square root | `sqrt(variance)` |
| `power(base, exp)` | Exponentiation | `power(2, 10)` |
| `log(n)` | Natural logarithm | `log(value)` |
| `log10(n)` | Base 10 logarithm | `log10(count)` |
| `exp(n)` | e to the power n | `exp(rate)` |
| `sign(n)` | Sign (-1, 0, 1) | `sign(delta)` |

### Conditional Functions

| Function | Description | Example |
|----------|-------------|---------|
| `if(cond, then, else)` | Conditional value | `if(status >= 400, "error", "ok")` |
| `case(cond1, val1, cond2, val2, ..., default)` | Multiple conditions | `case(status < 300, "success", status < 400, "redirect", status < 500, "client_error", "server_error")` |
| `coalesce(val1, val2, ...)` | First non-null | `coalesce(custom_name, default_name, "unknown")` |
| `isNull(val)` | Check if null | `isNull(error_message)` |
| `isNotNull(val)` | Check if not null | `isNotNull(user_id)` |
| `iif(cond, then, else)` | Inline if (alias) | `iif(count > 0, total/count, 0)` |

### Time Functions

| Function | Description | Example |
|----------|-------------|---------|
| `now()` | Current timestamp | `now()` |
| `today()` | Start of current day | `today()` |
| `bin(timestamp, interval)` | Bucket by time interval | `bin(timestamp, 5m)` |
| `formatTimestamp(ts, format)` | Format timestamp | `formatTimestamp(timestamp, "yyyy-MM-dd")` |
| `getYear(ts)` | Extract year | `getYear(timestamp)` |
| `getMonth(ts)` | Extract month (1-12) | `getMonth(timestamp)` |
| `getDay(ts)` | Extract day of month | `getDay(timestamp)` |
| `getHour(ts)` | Extract hour (0-23) | `getHour(timestamp)` |
| `getMinute(ts)` | Extract minute (0-59) | `getMinute(timestamp)` |
| `getSecond(ts)` | Extract second (0-59) | `getSecond(timestamp)` |
| `getDayOfWeek(ts)` | Day of week (1=Mon, 7=Sun) | `getDayOfWeek(timestamp)` |
| `getDayOfYear(ts)` | Day of year (1-366) | `getDayOfYear(timestamp)` |
| `timestampAdd(ts, duration)` | Add duration | `timestampAdd(timestamp, 1h)` |
| `timestampDiff(ts1, ts2)` | Difference in nanoseconds | `timestampDiff(end_time, start_time)` |
| `toUnixMillis(ts)` | Convert to Unix milliseconds | `toUnixMillis(timestamp)` |
| `toUnixSeconds(ts)` | Convert to Unix seconds | `toUnixSeconds(timestamp)` |
| `fromUnixMillis(n)` | Create from Unix milliseconds | `fromUnixMillis(1705315200000)` |
| `fromUnixSeconds(n)` | Create from Unix seconds | `fromUnixSeconds(1705315200)` |

### Duration Functions

| Function | Description | Example |
|----------|-------------|---------|
| `toDuration(nanos)` | Create duration from nanoseconds | `toDuration(1000000000)` |
| `toNanos(duration)` | Convert to nanoseconds | `toNanos(1s)` |
| `toMillis(duration)` | Convert to milliseconds | `toMillis(1h)` |
| `toSeconds(duration)` | Convert to seconds | `toSeconds(1d)` |
| `toMinutes(duration)` | Convert to minutes | `toMinutes(2h)` |
| `toHours(duration)` | Convert to hours | `toHours(1d)` |
| `toDays(duration)` | Convert to days | `toDays(168h)` |

### Array Functions

| Function | Description | Example |
|----------|-------------|---------|
| `size(array)` | Array length | `size(tags)` |
| `array_first(array)` | First element | `array_first(values)` |
| `array_last(array)` | Last element | `array_last(values)` |
| `array_concat(arr1, arr2)` | Concatenate arrays | `array_concat(tags1, tags2)` |
| `array_distinct(array)` | Remove duplicates | `array_distinct(values)` |
| `array_sort(array)` | Sort array | `array_sort(numbers)` |
| `array_reverse(array)` | Reverse order | `array_reverse(history)` |
| `array_slice(array, start, end)` | Extract subarray | `array_slice(items, 0, 5)` |
| `in_array(value, array)` | Check if in array | `in_array("error", tags)` |
| `array_join(array, delimiter)` | Join to string | `array_join(parts, "/")` |

### Record Functions

| Function | Description | Example |
|----------|-------------|---------|
| `record(key1: val1, ...)` | Create record | `record(name: "test", value: 42)` |
| `record_keys(record)` | Get keys as array | `record_keys(attributes)` |
| `record_values(record)` | Get values as array | `record_values(properties)` |
| `record_merge(rec1, rec2)` | Merge records | `record_merge(defaults, overrides)` |

### Network/IP Functions

| Function | Description | Example |
|----------|-------------|---------|
| `toIp(str)` | Parse IP address | `toIp("192.168.1.1")` |
| `ipInSubnet(ip, cidr)` | Check if IP in subnet | `ipInSubnet(client_ip, "10.0.0.0/8")` |
| `geoip_country(ip)` | Get country from IP | `geoip_country(client_ip)` |
| `geoip_city(ip)` | Get city from IP | `geoip_city(client_ip)` |

### Cryptographic Functions

| Function | Description | Example |
|----------|-------------|---------|
| `hash_md5(str)` | MD5 hash | `hash_md5(content)` |
| `hash_sha1(str)` | SHA1 hash | `hash_sha1(value)` |
| `hash_sha256(str)` | SHA256 hash | `hash_sha256(password)` |

---

## Pattern Language (DPL)

Dynatrace Pattern Language (DPL) is used with the `parse` command to extract structured data from unstructured text.

### Pattern Matchers

| Matcher | Description | Example |
|---------|-------------|---------|
| `LD` | Line data (any characters) | `LD:message` |
| `WORD` | Single word (no whitespace) | `WORD:method` |
| `INT` | Integer number | `INT:status` |
| `LONG` | Long integer | `LONG:id` |
| `DOUBLE` | Floating point number | `DOUBLE:latency` |
| `IPADDR` / `IP` | IP address (v4 or v6) | `IP:client_ip` |
| `TIMESTAMP` | Timestamp (ISO 8601) | `TIMESTAMP:time` |
| `SPACE` | One or more spaces | `SPACE` |
| `NSPACE` | One space | `NSPACE` |
| `EOL` | End of line | `EOL` |
| `JSON` | JSON object | `JSON:payload` |
| `DATA` | Greedy match all | `DATA:rest` |
| `UPPER` | Uppercase letters | `UPPER:code` |
| `LOWER` | Lowercase letters | `LOWER:name` |
| `ALPHA` | Letters only | `ALPHA:word` |
| `ALNUM` | Letters and numbers | `ALNUM:id` |
| `DIGIT` | Digits only | `DIGIT:count` |
| `HEXDIGIT` | Hexadecimal digits | `HEXDIGIT:hex` |
| `PUNCT` | Punctuation | `PUNCT:sep` |

### Pattern Syntax

```dql
// Basic extraction
parse content, "status=INT:status"

// Named capture with type
parse content, "IP:client_ip WORD:method LD:path INT:status_code"

// Literal text matching (quoted strings match exactly)
parse content, "'[' TIMESTAMP:time ']' WORD:level ':' LD:message"

// Optional sections
parse content, "LD ('error:' LD:error_msg)?"

// Alternatives
parse content, "status=('OK'|'ERROR'):status"

// Quantifiers
parse content, "WORD{3}:three_words"         // Exactly 3
parse content, "DIGIT{2,4}:code"              // 2 to 4 digits
parse content, "WORD+:words"                  // One or more
parse content, "WORD*:optional_words"         // Zero or more
```

### Common Parsing Patterns

```dql
// Apache/NGINX access log
parse content, """
    IP:client_ip
    SPACE '-' SPACE
    LD:user
    SPACE '['
    TIMESTAMP('dd/MMM/yyyy:HH:mm:ss Z'):time
    '] "'
    WORD:method
    SPACE
    LD:path
    SPACE
    LD:protocol
    '" '
    INT:status
    SPACE
    INT:bytes
"""

// Key-value pairs
parse content, "LD 'key1=' LD:val1 ', key2=' LD:val2"

// JSON in log
parse content, "LD JSON:payload"

// Stack trace first line
parse content, "LD:exception_class ':' LD:message"
```

---

## Best Practices

### Query Performance

1. **Apply filters early** - Filter data as close to `fetch` as possible:
   ```dql
   // Good: filter immediately
   fetch logs
   | filter loglevel == "ERROR"
   | filter contains(content, "timeout")
   | summarize count()

   // Bad: filter late
   fetch logs
   | summarize count(), by: {loglevel, content}
   | filter loglevel == "ERROR"
   ```

2. **Use `scanLimitGBytes`** for large queries:
   ```dql
   fetch logs, scanLimitGBytes: 100
   ```

3. **Limit time range** - Query only needed timeframe:
   ```dql
   fetch logs, from: now() - 1h
   ```

4. **Use `matchesPhrase` for text search** - More efficient than `contains`:
   ```dql
   // Better for indexed text search
   | filter matchesPhrase(content, "connection timeout")

   // Less efficient
   | filter contains(content, "connection timeout")
   ```

5. **Use `countDistinctApprox` for high-cardinality** - Faster than `countDistinct`:
   ```dql
   | summarize countDistinctApprox(session_id)
   ```

6. **Avoid SELECT * equivalent** - Specify needed fields:
   ```dql
   // Good
   | fields timestamp, content, loglevel

   // Avoid - returns all fields
   ```

### Common Patterns

#### Error Analysis
```dql
fetch logs, from: now() - 1h
| filter loglevel == "ERROR"
| summarize
    error_count = count(),
    by: {bin(timestamp, 5m), log.source}
| sort error_count desc
```

#### Top N Pattern
```dql
fetch logs
| summarize count = count(), by: {host.name}
| sort count desc
| limit 10
```

#### Percentile Latency
```dql
fetch spans
| summarize
    p50 = percentile(duration, 50),
    p95 = percentile(duration, 95),
    p99 = percentile(duration, 99),
    by: {span.name}
```

#### Time Bucketing
```dql
fetch logs
| summarize count(), by: {bin(timestamp, 15m)}
| sort timestamp asc
```

#### Null-Safe Operations
```dql
fetch logs
| fieldsAdd safe_field: coalesce(optional_field, "default")
| filter isNotNull(required_field)
```

#### Conditional Aggregation
```dql
fetch logs
| summarize
    total = count(),
    errors = countIf(loglevel == "ERROR"),
    warnings = countIf(loglevel == "WARN"),
    error_rate = 100.0 * countIf(loglevel == "ERROR") / count()
```

#### Multi-Source Analysis
```dql
fetch logs, from: now() - 1h
| filter loglevel == "ERROR"
| lookup [fetch entities | fields id, name: entity.name],
         sourceField: dt.entity.host, lookupField: id
| fields timestamp, content, host_name: name
```

#### Time Series Creation
```dql
fetch logs
| filter loglevel == "ERROR"
| summarize count(), by: {bin(timestamp, 5m), service.name}
| makeTimeseries count(), by: {service.name}, time: timestamp
```

### Debugging Queries

1. **Start simple, add complexity** - Build query incrementally:
   ```dql
   // Step 1: Verify data
   fetch logs | limit 10

   // Step 2: Add filter
   fetch logs | filter loglevel == "ERROR" | limit 10

   // Step 3: Add aggregation
   fetch logs | filter loglevel == "ERROR" | summarize count()
   ```

2. **Use `limit` during development** - Avoid scanning full dataset:
   ```dql
   fetch logs
   | filter complex_condition
   | limit 100  // Remove after testing
   ```

3. **Check field names** - Use `fields *` to see available fields:
   ```dql
   fetch logs | limit 1
   // Inspect available fields in result
   ```

---

## Quick Reference Card

### Time Shortcuts
- `now()` - Current time
- `now() - 1h` - 1 hour ago
- `now() - 24h` - 24 hours ago
- `now() - 7d` - 7 days ago

### Duration Units
- `ns` - nanoseconds
- `us` - microseconds
- `ms` - milliseconds
- `s` - seconds
- `m` - minutes
- `h` - hours
- `d` - days

### Common Filters
```dql
| filter field == "value"           // Equality
| filter field != "value"           // Inequality
| filter field > 100                // Comparison
| filter field in ("a", "b", "c")   // Membership
| filter contains(field, "text")    // Substring
| filter matches(field, "regex")    // Regex
| filter isNotNull(field)           // Not null
```

### Common Aggregations
```dql
| summarize count()                           // Count all
| summarize count(), by: {field}              // Group by
| summarize avg(metric), by: {bin(time, 5m)}  // Time series
| sort field desc | limit 10                  // Top N
```

---

*This reference is designed for use with Claude Sonnet 4.5 and Claude Opus 4.5 for Dynatrace query generation and analysis.*
