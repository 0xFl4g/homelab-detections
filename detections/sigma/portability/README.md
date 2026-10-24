# Portability-only Sigma rules

Sigma source kept for portability but NOT converted by `../convert-elastic.sh` (which globs
`../rules/lab/` only). These express detections whose runtime form is native EQL on data the
process-creation pipeline does not map (auditd file watches, etc). The live rule is in
`detections/native/`.
