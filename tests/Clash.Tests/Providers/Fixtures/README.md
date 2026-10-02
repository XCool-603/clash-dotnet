# MRS test fixtures

Real, published `.mrs` rule sets, used as decode vectors by
`MrsDecoderTests`. They are kept in the repository rather than downloaded at
test time so the suite is hermetic and so a format change shows up as a diff in
a file that was produced by the reference implementation, not by this one.

| file | source | behaviour |
|---|---|---|
| `geosite-category-ads-all.mrs` | [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat), `meta` branch, `geo/geosite/category-ads-all.mrs` | domain |
| `geosite-cn.mrs` | same, `geo/geosite/cn.mrs` | domain |
| `geoip-cn.mrs` | same, `geo/geoip/cn.mrs` | ipcidr |
| `asn-AS13335.mrs` | same, `asn/AS13335.mrs` | ipcidr |

All four begin with the zstd magic `28 b5 2f fd`: the whole file is a zstd
stream, which is why the provider loader reads rule-set bodies as bytes rather
than text.

`geosite-category-ads-all.mrs` is the strongest vector here, because the same
list is also published as YAML: the test suite compares the decoded entries
against that twin, which pins the output to what the reference implementation
produces rather than to what this decoder happens to emit.
