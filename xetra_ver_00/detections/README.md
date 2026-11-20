# Detection Content

Sigma rules (https://github.com/SigmaHQ/sigma — the open, vendor-neutral
detection-rule standard) for a representative set of XETRA/ARTEX-mapped
techniques. These are *detection logic*, the defensive mirror of an
attack technique, not attack code — the same kind of content every SOC
and SIEM vendor publishes openly.

Convert to your SIEM's native query language with `sigma-cli`
(https://github.com/SigmaHQ/sigma-cli), e.g.:

    pip install sigma-cli
    sigma convert -t splunk detections/t1558_003_kerberoasting.yml
    sigma convert -t sentinel detections/t1003_credential_dumping.yml

Map the resulting query into `config.yaml` under the relevant SIEM
adapter's `query_map` so HUNT's SIEM check actually queries for it.
