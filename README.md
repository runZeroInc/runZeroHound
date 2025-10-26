# runZeroHound

Bring runZero Exposure Management into BloodHound via [OpenGraph](https://bloodhound.specterops.io/opengraph/overview).

## Getting Started

1. Export your runZero assets as JSONL from the Export menu in the runZero Asset Inventory.

2. Execute runZeroHound with the convert command to transform the assets.jsonl to a BloodHound OpenGraph import.

```
$ go run main.go convert assets.jsonl runzero-opengraph.json
```

3. Upload runzero-opengraph.json into the BloodHound user interface.

4. Optionally load the model.json into BloodHound for customized icons.




