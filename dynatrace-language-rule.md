# Dynatrace Query Language (DQL) Rule

> **LLM Context**: This file provides guidance for LLMs generating DQL queries. Use this as a quick reference when constructing queries with the `execute_dql` tool or when helping users understand DQL syntax.

You are an expert in Dynatrace Query Language (DQL) for querying the Dynatrace Grail data lakehouse. When helping users write or understand DQL queries, follow these guidelines.

## Core Principles

1. **Pipeline-first**: DQL uses pipeline syntax with `|` operator. Data flows from `fetch` through transformations.
2. **Filter early**: Apply filters immediately after `fetch` for optimal performance.
3. **Explicit fields**: Select only needed fields to reduce data transfer.
4. **Time-aware**: Always consider time ranges; default to narrow ranges for performance.

## Query Structure Template

```dql
fetch <data_source>, from: <start_time>, to: <end_time>
| filter <conditions>
| fieldsAdd <computed_fields>
| summarize <aggregations>, by: {<group_by_fields>}
| sort <field> <direction>
| limit <count>
```

## Data Sources Reference

| Source | Use For | Key Fields |
|--------|---------|------------|
| `logs` | Log analysis, debugging | `timestamp`, `content`, `loglevel`, `log.source` |
| `events` | Davis events, custom events | `timestamp`, `event.type`, `event.name`, `event.kind` |
| `metrics` | Metric queries | `timestamp`, `metric.key`, `value` |
| `spans` | Distributed tracing | `timestamp`, `span.name`, `trace.id`, `duration` |
| `entities` | Entity metadata | `entity.type`, `entity.name`, `id`, `tags` |
| `bizevents` | Business events | `timestamp`, `event.type`, custom attributes |

## Common Query Patterns

### Error Analysis
```dql
fetch logs, from: now() - 1h
| filter loglevel == "ERROR"
| summarize count = count(), by: {log.source, bin(timestamp, 5m)}
| sort count desc
```

### Top N Pattern
```dql
fetch logs
| summarize count = count(), by: {host.name}
| sort count desc
| limit 10
```

### Percentile Latency
```dql
fetch spans, from: now() - 1h
| summarize p50 = percentile(duration, 50), p95 = percentile(duration, 95), p99 = percentile(duration, 99), by: {span.name}
```

### Time Series
```dql
fetch logs
| summarize count(), by: {bin(timestamp, 5m)}
| sort timestamp asc
```

### Text Search
```dql
fetch logs
| filter matchesPhrase(content, "connection timeout")
```

### Conditional Counting
```dql
fetch logs
| summarize total = count(), errors = countIf(loglevel == "ERROR"), error_rate = 100.0 * countIf(loglevel == "ERROR") / count()
```

### Join with Entities
```dql
fetch logs
| lookup [fetch entities | fields id, name: entity.name], sourceField: dt.entity.host, lookupField: id
```

### Parse Structured Data
```dql
fetch logs
| parse content, "status=INT:status duration=INT:duration_ms"
| filter status >= 400
```

## Key Functions Quick Reference

### Aggregation
- `count()`, `countIf(condition)`, `countDistinct(field)`
- `sum(field)`, `avg(field)`, `min(field)`, `max(field)`
- `percentile(field, p)`, `median(field)`, `stddev(field)`

### String
- `contains(str, substr)`, `startsWith()`, `endsWith()`
- `matches(str, regex)`, `matchesPhrase(str, phrase)`
- `lower()`, `upper()`, `trim()`, `replace()`, `split()`

### Time
- `now()`, `bin(timestamp, interval)`, `formatTimestamp()`
- `getYear()`, `getMonth()`, `getDay()`, `getHour()`
- `timestampAdd()`, `timestampDiff()`

### Conditional
- `if(condition, then, else)`, `case(cond1, val1, ..., default)`
- `coalesce(val1, val2, ...)`, `isNull()`, `isNotNull()`

## Performance Guidelines

1. **Use `scanLimitGBytes`** for large queries:
   ```dql
   fetch logs, scanLimitGBytes: 100
   ```

2. **Prefer `matchesPhrase` over `contains`** for text search (uses indexes)

3. **Use `countDistinctApprox`** for high-cardinality fields

4. **Filter by time first**, then by other conditions

5. **Use `limit` during development** to test queries quickly

## Pattern Language (DPL) for Parsing

Common matchers:
- `LD` - Any characters (line data)
- `INT` - Integer
- `DOUBLE` - Decimal number
- `IP` - IP address
- `WORD` - Single word
- `TIMESTAMP` - ISO timestamp
- `SPACE` - Whitespace
- `JSON` - JSON object

Example:
```dql
fetch logs
| parse content, "IP:client_ip SPACE WORD:method SPACE LD:path SPACE INT:status"
```

## Operators Reference

| Operator | Description | Example |
|----------|-------------|---------|
| `==`, `!=` | Equality | `status == 200` |
| `<`, `<=`, `>`, `>=` | Comparison | `latency > 1000` |
| `and`, `or`, `not` | Logical | `a and b` |
| `in` | Membership | `status in (200, 201)` |
| `~` | Pattern match | `content ~ "error.*"` |
| `+`, `-`, `*`, `/`, `%` | Arithmetic | `total / count` |

## Duration Units

`ns` (nanoseconds), `us` (microseconds), `ms` (milliseconds), `s` (seconds), `m` (minutes), `h` (hours), `d` (days)

## Common Mistakes to Avoid

1. **Filtering after aggregation** - Always filter before `summarize`
2. **Missing time range** - Always specify `from:` for large datasets
3. **Using `contains` for indexed search** - Use `matchesPhrase` instead
4. **Forgetting `by:` in summarize** - Results in single aggregated row
5. **Not handling nulls** - Use `coalesce()` or `isNotNull()` filters

## Response Format

When generating DQL queries:
1. Start with the simplest working query
2. Add comments for complex logic
3. Explain the query structure
4. Suggest optimizations if applicable
5. Provide variations for common modifications

Reference: See `dynatrace-language-reference.md` for complete DQL documentation.

---

## Quick Decision Guide for LLMs

| User Request | Recommended Approach |
|--------------|---------------------|
| "Show me errors" | `fetch logs \| filter loglevel == "ERROR"` |
| "How many X per Y" | Use `summarize count(), by: {field}` |
| "Trend over time" | Use `summarize count(), by: {bin(timestamp, 5m)}` |
| "Slowest services" | `fetch spans \| summarize avg(duration), by: {span.name} \| sort avg(duration) desc` |
| "Find text in logs" | Use `matchesPhrase(content, "search term")` |
| "Join with entities" | Use `lookup` command |
| "Parse log format" | Use `parse` with DPL matchers |

## Tool Mapping

- **Natural language query** -> Use `generate_dql_from_natural_language` first
- **Validate query syntax** -> Use `verify_dql` before expensive queries
- **Execute query** -> Use `execute_dql` with properly formed DQL
- **Explain existing query** -> Use `explain_dql_in_natural_language`
