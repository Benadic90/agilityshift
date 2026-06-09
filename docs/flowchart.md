# Flowchart

```text
[ Target Codebase ]
        |
        v
+-------------------+
|   CLI Scanner     |
+-------------------+
        |
        +---> [ Code Limit Detector ]
        |
        +---> [ DB Schema Detector ]
        |
        +---> [ API Schema Detector ]
        |
        v
+-------------------+      +-------------------+
|   Risk Scorer     |<-----|   PQC Profiles    |
+-------------------+      +-------------------+
        |
        v
+-------------------+
|  Report Generator |
+-------------------+
        |
        v
[ CI / CD Exit ]
```
