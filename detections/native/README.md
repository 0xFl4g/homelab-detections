# Native Elastic detection rules (lab)

Rules the Sigma→Elastic converter cannot express well (auditd file watches, multi-event
sequences). Kept here as the source of record; a matching Sigma file under
`../sigma/rules/lab/` carries the portable intent. Push:

    cat detections/native/<id>.json | ssh unraid 'cd /boot/config/compose/elastic && bash rules-add.sh && bash rules-sync.sh'

`rules-add.sh` applies the house defaults (enabled, interval 5m, from now-6m).
