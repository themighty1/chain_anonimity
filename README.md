Analysis of anonymity distribution of TLS certificate chains of TOP 1000 websites.

All the chains have been pre-downloaded to the `chains` folder.

To see the results, run:
```
cargo run --release --bin parse_chains
```

The result is:
```
Total 913 fingerprints in 36 pools
Pool size  % of total         Pool fingerprint (chain_length|sig|sig|...)

280        30         3|RSA-2048-SHA256|RSA-2048-SHA256
135        45         4|RSA-2048-SHA256|RSA-2048-SHA256|RSA-2048-SHA256
109        57         3|RSA-2048-SHA256|RSA-4096-SHA256
98         68         4|ECDSA-P256-SHA256|ECDSA-P384-SHA384|RSA-2048-SHA256
67         75         3|ECDSA-P384-SHA384|RSA-4096-SHA256
61         82         5|RSA-2048-SHA256|RSA-2048-SHA256|RSA-2048-SHA256|RSA-2048-SHA256
37         86         4|RSA-2048-SHA256|RSA-4096-SHA384|RSA-2048-SHA384
24         88         4|RSA-2048-SHA256|RSA-4096-SHA256|RSA-2048-SHA256
18         90         3|RSA-2048-SHA256|RSA-4096-SHA384
13         92         4|RSA-3072-SHA384|RSA-4096-SHA384|RSA-2048-SHA384
12         93         3|ECDSA-P384-SHA384|RSA-2048-SHA384
9          94         3|ECDSA-P384-SHA384|ECDSA-P384-SHA384
6          95         4|RSA-2048-SHA256|RSA-4096-SHA256|RSA-2048-SHA384
5          95         4|ECDSA-P256-SHA256|ECDSA-P384-SHA384|RSA-2048-SHA384
5          96         3|RSA-3072-SHA384|RSA-4096-SHA384
5          96         3|RSA-4096-SHA256|RSA-2048-SHA256
4          97         3|RSA-4096-SHA384|RSA-2048-SHA384
2          97         4|RSA-4096-SHA256|RSA-2048-SHA256|RSA-2048-SHA256
2          97         4|RSA-4096-SHA256|RSA-4096-SHA256|RSA-4096-SHA256
2          97         4|RSA-2048-SHA256|RSA-4096-SHA384|RSA-4096-SHA384
2          98         4|RSA-4096-SHA384|RSA-4096-SHA384|RSA-2048-SHA384
2          98         3|ECDSA-P256-SHA256|ECDSA-P384-SHA256
2          98         3|ECDSA-P256-SHA256|RSA-2048-SHA256
1          98         3|ECDSA-P256-SHA256|ECDSA-P384-SHA384
1          98         4|RSA-2048-SHA256|RSA-2048-SHA256|RSA-4096-SHA384
1          98         4|ECDSA-P256-SHA384|ECDSA-P384-SHA384|RSA-4096-SHA256
1          99         3|RSA-4096-SHA384|RSA-4096-SHA384
1          99         3|RSA-4096-SHA256|RSA-4096-SHA256
1          99         3|RSA-2048-SHA512|RSA-2048-SHA256
1          99         4|ECDSA-P256-SHA256|ECDSA-P256-SHA256|RSA-2048-SHA256
1          99         3|RSA-4096-SHA256|RSA-2048-SHA384
1          99         4|RSA-2048-SHA256|RSA-2048-SHA256|RSA-4096-SHA256
1          99         5|RSA-2048-SHA256|RSA-4096-SHA1|RSA-2048-SHA384|RSA-4096-SHA384
1          99         5|RSA-2048-SHA256|RSA-2048-SHA256|RSA-4096-SHA384|RSA-2048-SHA384
1          99         4|RSA-4096-SHA384|RSA-3072-SHA384|RSA-4096-SHA384
1          100        4|RSA-2048-SHA384|RSA-3072-SHA1|RSA-4096-SHA384
```


If you need to re-download the chains, delete the `chains` folder and run
```
cargo run --release --bin fetch_chains
```